"""Audit real files and direct PCAP exports; emit evidence before any model fit."""
import argparse
import csv
import json
import platform
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from .common import epoch_ns, frame_key, load_config, read_csv, sha256, unique_index, write_csv, write_json
from .feature_extraction import feature_availability, stream_quality, temporal_discontinuities
from .label_validation import IDENTITY_STATUSES, audit_label_join, identity_status, training_gate
from .pcap_tools import BASE_FIELDS, EXTRA_FIELDS
from .preprocessing import FORBIDDEN

COMPARE_COLUMNS = ['frame_time_epoch', 'frame_len', 'bssid', 'ssid_hex', 'tsf',
                   'beacon_interval_tu', 'capabilities', 'sequence_number', 'ie_tag_ids',
                   'rsn_version', 'radiotap_rssi_dbm', 'radiotap_channel_freq']


def canonical(value, field):
    if value == '':
        return None
    if field == 'frame_time_epoch':
        return epoch_ns(value)
    if field in ('frame_len', 'tsf', 'beacon_interval_tu', 'sequence_number', 'radiotap_channel_freq', 'rsn_version'):
        return int(value)
    if field in ('capabilities', 'subtype'):
        return int(value, 0)
    if field in ('radiotap_rssi_dbm', 'ie_tag_ids'):
        return tuple(int(x) for x in value.replace(',', ';').split(';'))
    return value.lower()


def compare_frames(expected, observed, columns):
    left, right = unique_index(expected), unique_index(observed)
    result = []
    for key in sorted(left.keys() | right.keys()):
        bad = []
        if key not in left or key not in right:
            bad.append('missing_original_record' if key not in left else 'missing_reextracted_record')
        else:
            for field in columns:
                try:
                    if canonical(left[key][field], field) != canonical(right[key][field], field):
                        bad.append(field)
                except (ValueError, ArithmeticError):
                    bad.append(field + '_parse_error')
        result.append(dict(pcap=key[0], frame_number=key[1], agrees=not bad,
                           mismatched_fields=';'.join(bad)))
    return result


def profile_csv(path, root):
    # Stream schema/count/missing analysis even for label tables.
    with path.open(newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        columns = reader.fieldnames
        if not columns or len(columns) != len(set(columns)):
            raise ValueError(f'Missing or duplicate CSV columns: {path}')
        missing = Counter(); types = {col: set() for col in columns}; count = 0
        keys = set(); duplicates = 0
        keyed = 'pcap' in columns and 'frame_number' in columns
        unique_values = {col: set() for col in columns if col in ('bssid', 'wlan.bssid', 'ssid_hex', 'wlan.ssid', 'beacon_role_label', 'attack_related_label', 'attack_label_status')}
        for r in reader:
            if None in r or any(v is None for v in r.values()):
                raise ValueError(f'Ragged CSV record {count + 1}: {path}')
            count += 1
            for col, value in r.items():
                if value == '':
                    missing[col] += 1
                else:
                    kind = 'integer' if re.fullmatch(r'[+-]?\d+', value) else (
                        'decimal' if re.fullmatch(r'[+-]?\d+\.\d+', value) else 'string')
                    types[col].add(kind)
                if col in unique_values:
                    unique_values[col].add(value)
            if keyed:
                key = frame_key(r)
                duplicates += key in keys
                keys.add(key)
    return dict(path=path.relative_to(root).as_posix(), sha256=sha256(path), rows=count,
        columns=[dict(name=c, inferred_type='|'.join(sorted(types[c])) or 'all_empty',
                      storage='string; preserve integer/Decimal timestamps', missing=missing[c],
                      missing_fraction=missing[c] / count if count else None) for c in columns],
        duplicate_capture_frame_keys=duplicates if keyed else None,
        duplicate_scope='capture+original frame' if keyed else 'no capture-keyed frame schema; not a frame table or capture inferred separately',
        unique_values={c: sorted(v) for c, v in unique_values.items()})


def shortcut_profile(rows):
    result = []
    fields = ['capabilities', 'frame_len', 'rsn_version', 'radiotap_channel_freq', 'beacon_interval_tu', 'ie_tag_ids']
    groups = defaultdict(list)
    for r in rows:
        groups[(r['pcap'], r['identity_status'])].append(r)
    for (pcap, status), g in sorted(groups.items()):
        for field in fields:
            counts = Counter(r[field] for r in g)
            result.append(dict(pcap=pcap, identity_status=status, field=field, rows=len(g),
                               distinct_values=len(counts), values_and_counts=json.dumps(dict(sorted(counts.items())), ensure_ascii=False),
                               interpretation='Descriptive audit only; do not use this full-data table for feature selection'))
    return result


def previous_overlap(windows, rows):
    evil = [r for r in rows if r['identity_status'] == 'candidate_evil_twin']
    if not evil:
        return []
    first = min(int(r['frame_number']) for r in evil)
    groups = defaultdict(Counter)
    for w in windows:
        g = groups[w['split']]
        g['candidate_windows'] += 1
        if w['valid'] == 'True':
            g['valid_windows'] += 1
            g['valid_before_first_observed_evil'] += int(w['last_frame']) < first
            g['valid_after_first_observed_evil'] += int(w['first_frame']) >= first
            g['valid_straddling_first_observed_evil'] += int(w['first_frame']) < first <= int(w['last_frame'])
    cols = ['candidate_windows', 'valid_windows', 'valid_before_first_observed_evil',
            'valid_after_first_observed_evil', 'valid_straddling_first_observed_evil']
    return [dict(split=k, **{c: v[c] for c in cols}) for k, v in groups.items()]


def write_report(out, audit, evidence):
    gate = audit['training_gate']; counts = gate['identity_counts']; checks = audit['checks']
    lines = [
        '# Dataset audit และ label verification — รอบแรก', '',
        '## ขอบเขตและผลตัดสิน', '',
        '**ยังไม่อนุญาต supervised training ตามนิยาม verified ใน protocol รอบนี้**: '
        'มีหลักฐานบทความผู้จัดทำรองรับ dataset-role mapping แต่ไม่มี independent device/event logs '
        'และยังไม่ได้รับการยอมรับ proposed labeling protocol สำหรับใช้ candidate roles เป็น training targets.', '',
        'คำว่า verified ในรายงานนี้หมายถึงตัวตนอุปกรณ์ที่มีหลักฐานอิสระผูกกับ capture '
        'ไม่ใช่เพียงตรวจว่า CSV ตรงกับ PCAP หรือ attack filter. '
        'การแยกสถานะนี้ไม่ได้หักล้างคำอธิบาย testbed ของผู้จัดทำหรือ NORMAL labels ในงานเดิม.', '',
        '## สิ่งที่ตรวจยืนยันได้จากไฟล์', '',
        f'- พบ capture files {len(audit["pcaps"])} ไฟล์ (รวม derived pcapng); original PCAP {sum(p["pcap"].endswith(".pcap") for p in audit["pcaps"])} ไฟล์.',
        f'- labeled beacon {audit["labeled_beacons"]:,} แถว; attack-frame label table {audit["attack_label_rows"]:,} แถว.',
        '- ใช้ primary key `(pcap path, original frame number)` และตรวจ uniqueness ก่อน join; ไม่ใช้ row index.',
        '- นับเฟรมและ hash PCAP ทุกไฟล์ด้วย capinfos; re-extract Beacon และ replay filter ทางการจาก Read_me.txt เฉพาะ Evil_Twin/Rogue_AP.',
        '- อ่าน PCAP ผ่าน TShark subprocess ลง CSV โดยตรง; ไม่โหลด PCAP ทั้งก้อนใน RAM.', '',
        '| การตรวจ | ผล |', '|---|---|',
    ]
    lines += [f'| {name} | {value} |' for name, value in checks.items()]
    lines += ['', 'ผล integrity ใช้ canonical labeled CSV/attack-label CSV เทียบ PCAP โดยตรง. '
        'ไฟล์ raw CSV เดิมเป็นหลักฐานเสริมและแยกรายงานความต่าง ไม่ให้การขาดแถวในสำเนาเสริม '
        'กลายเป็นข้อสรุปว่า canonical labels ผิด.', '',
        '| Capture | เฟรมทั้งหมด | Beacon | ตรง official filter ทุกชนิดเฟรม |',
        '|---|---:|---:|---:|']
    lines += [f'| {p["pcap"]} | {p["total_frames"]:,} | {p["beacon_count"]:,} | {p["exact_filter_match_count"]:,} |'
              for p in audit['pcaps'] if p['beacon_count'] != '']
    lines += ['', '| Identity status | จำนวน |', '|---|---:|']
    lines += [f'| {name} | {counts[name]:,} |' for name in IDENTITY_STATUSES]
    lines += ['', '## หลักฐานและข้อสมมติ', '',
        f'- [บทความผู้จัดทำ]({evidence["source_url"]}), DOI {evidence["doi"]}, หัวข้อ Evil_Twin '
        'อธิบาย MAC suffix ของ rogue ต่างจาก legitimate และใช้ configuration เดิมใน implementation ถัดไป.',
        '- Read_me.txt ระบุ full address ใน filter; การรวมหลักฐานนี้กับ role mapping เดิมรองรับ candidate roles '
        'สำหรับ capture นี้ แต่ไม่ใช่การตรวจยืนยันตัวส่งจาก MAC เพียงอย่างเดียว.',
        '- เก็บ attack_related_label, attack_label_status และ legacy beacon_role_label เดิมไว้ครบ '
        'แล้วเพิ่ม identity_status กับ evidence_id; unknown ไม่ถูกแทนด้วย NORMAL.',
        '- Rogue_AP ใช้ same-BSSID และไม่มี identity annotations ที่แยกอุปกรณ์ได้ในชุดนี้ จึงคง unknown ทั้ง capture.',
        '- แถวที่ไม่ตรง filter ไม่ได้แปลว่าปกติ; ช่วงก่อน/หลัง filter ไม่ใช่ device power-on/off logs.', '',
        '## ความเสี่ยง leakage และ shortcut', '',
        '- ห้าม predictive inputs: SSID/BSSID/MAC, frame number, absolute timestamp, raw TSF, capture filename/scenario, stream ID และ label/provenance ทุกชนิด.',
        '- `src/preprocessing.py` ใช้ feature allowlist; ชื่ออื่นถูกปฏิเสธ เพื่อไม่หลุดด้วยการ rename ฟิลด์.',
        '- Capability/RSN/IE/rates/frame length อาจจำ configuration ของ AP; frame length ยังเป็นส่วนหนึ่งของ filter '
        'จึงเสี่ยง label-definition shortcut หากนำ filter matches เป็น target.',
        '- RSSI อาจแทนตำแหน่ง receiver; channel/beacon interval อาจคงที่ ต้องตัดสินความคงที่จาก train เท่านั้น.',
        '- ไม่แบ่ง beacon แบบ random; มี Evil_Twin session เดียว จึงยังทดสอบ unseen physical AP ไม่ได้.',
        '- การแบ่งตามเวลาอาจทำให้ train ไม่มี class โจมตี หรือเห็นเพียง profile แรก ต้องตรวจ class/profile support ก่อน fit.',
        '- ตาราง shortcut ใน audit ใช้อธิบายข้อจำกัด ไม่ใช้เลือกฟีเจอร์จาก test data.', '',
        '## ฟีเจอร์และคุณภาพ', '',
        '- feature_availability.csv ระบุ field จริง วิธีคำนวณที่เสนอ อัตราว่างระดับ source-frame และความเสี่ยงราย feature/capture.',
        '- Configuration: capabilities, RSN presence/capabilities, cipher/AKM suites, supported rates, selected IE structure, beacon interval.',
        '- Radio: antenna RSSI, frequency; ยังไม่มี independent receiver capture เพื่อรับรอง field compatibility.',
        '- Frame: length, modulo-4096 sequence increments, retry. Sequence jump ไม่พิสูจน์ beacon loss.',
        '- Temporal: receive time/TSF มีให้คำนวณ interarrival/MAD/slope; stream_quality.csv รายงาน gaps/nonpositive deltas. '
        'ต้องไม่ regress ข้าม TSF reset และต้องแยก candidate streams.',
        '- RSN fields ว่างใน open profile เป็น structural absence ได้ ไม่ควรเติม cipher เอง; '
        'RSN presence ต้องอาศัย IE parsing ที่สมบูรณ์.',
        '- ใช้ timestamp แบบ Decimal/integer ns ไม่แปลง absolute epoch เป็น float; '
        'CSV summary เก่าบางไฟล์มีเศษเวลาจาก float จึงไม่ใช้เป็นฐาน join.',
        '- full_capture_inventory.csv นับ total frames ครบ; beacon count ของ captures นอกสองกรณีที่ตรวจเป็นช่องว่าง (not inspected), ไม่ใช่ศูนย์.',
        '- derived pcapng มีเลขเฟรมใหม่ ห้าม join กับ source capture ด้วยหมายเลขเฟรมตรง ๆ.', '',
        f'- พบ supplemental raw CSV discrepancies {checks["raw_csv_mismatches"]} แถว; '
        'ดู raw_csv_join_audit.csv. ในข้อมูลรอบนี้ Rogue_AP.csv ขาดเฟรม 211266 และ 231295 '
        'แต่ PCAP/labeled CSV มีทั้งสองเฟรม และขาด fixed beacon fields ตาม flagged_beacons.csv. '
        'ไม่ทราบเหตุผลการคัดออกใน exporter เก่า จึงไม่ใช้ไฟล์เสริมนี้แทน PCAP.',
        f'- พบ nonpositive temporal boundaries ภายใน diagnostic streams {audit["temporal_discontinuity_count"]} จุด; '
        'ดู temporal_discontinuities.csv. ต้อง flag หน้าต่างที่ข้ามจุดเหล่านี้ ไม่คำนวณ slope ข้าม reset.', '',
        '## ผลกระทบต่อ Time-Shield เดิม', '',
        'ดู previous_time_shield_overlap.csv: enrollment อยู่ก่อน first observed rogue; calibration คร่อมช่วงนั้น '
        'และ holdout อยู่หลังเริ่มพบ rogue. การแจ้งเตือนบน legitimate stream ไม่เท่ากับ FPR ในสภาพแวดล้อมปลอดโจมตี. '
        'งานนี้ไม่แก้ baseline ไม่ fit ซ้ำ และไม่ปรับ threshold.', '',
        '## สิ่งที่ยังไม่ได้ทำและทางไปต่อ', '',
        'ขั้นตอน 1–3 ของ execution list เสร็จในขอบเขต audit นี้. ยังไม่สร้าง window feature datasets, '
        'split สำหรับ ML, model artifacts, performance metrics, ablation หรือ fusion. '
        'ต้องยอมรับ labeling_protocol.md ก่อนใช้ candidate roles เป็น targets หรือเพิ่ม independent device/event evidence.', '',
        'จากนั้นสร้างหน้าต่าง 10/20/50 beacon พร้อม conservative mixed/unknown policy, ตรวจ chronology/class support, '
        'fit preprocessing เฉพาะ train และทดลอง CART/RF/LR ก่อนเชื่อม Time-Shield. '
        'รายงาน preliminary same-capture performance แยกจาก independent-AP evaluation ซึ่งยังไม่มีข้อมูล.', '',
        'ผลตรวจ CSV/PCAP สอดคล้องกันไม่ใช่การรับรอง identity โดยตัวมันเอง และไม่มีการสร้างข้อมูลหรือ metrics เทียม.',
    ]
    (out / 'data_quality_report.md').write_text('\n'.join(lines) + '\n')


def run(config_path, dataset_root, extraction_dir, out):
    config, root = load_config(config_path, dataset_root)
    if out.exists() and any(out.iterdir()):
        raise FileExistsError('Audit output exists; use a fresh --out directory')
    out.mkdir(parents=True, exist_ok=True)
    evidence_path = config_path.resolve().parent / config['identity_evidence']
    evidence = json.loads(evidence_path.read_text())
    extraction = json.loads((extraction_dir / 'extraction_manifest.json').read_text())
    if extraction['config_sha256'] != sha256(config_path):
        raise ValueError('Extraction/config hash mismatch; rerun extraction in a fresh directory')
    if extraction['source_readme_sha256'] != sha256(root / config['readme']):
        raise ValueError('README changed since extraction')
    for item in extraction['extractions']:
        if sha256(extraction_dir / item['output']) != item['output_sha256']:
            raise ValueError(f'Extracted CSV hash mismatch: {item["output"]}')
    labels_path = root / config['labeled_csv']; attacks_path = root / config['attack_labels_csv']
    labels, attacks = read_csv(labels_path), read_csv(attacks_path)
    unique_index(labels); unique_index(attacks)
    join = audit_label_join(labels, attacks)
    write_csv(out / 'frame_label_join_audit.csv', join)
    validated = []
    for row in labels:
        status, source = identity_status(row, config['label_policy'])
        validated.append(dict(row, identity_status=status, identity_evidence_id=source,
                              supervised_target='', supervised_eligible=False))
    write_csv(out / 'identity_label_audit.csv', validated)
    actual_by_capture = {}; pcap_comparisons = []; filter_comparisons = []; raw_comparisons = []
    extraction_fields = BASE_FIELDS | EXTRA_FIELDS
    filter_counts = {}
    for capture in config['captures']:
        scenario, name = capture['scenario'], capture['pcap']
        rows = [dict(pcap=name, **{extraction_fields[k]: v for k, v in r.items()})
                for r in read_csv(extraction_dir / f'{scenario}_beacons.csv')]
        unique_index(rows)
        if any(int(r['subtype'], 0) != 8 for r in rows):
            raise ValueError('Non-beacon in beacon extraction')
        actual_by_capture[name] = rows
        expected = [r for r in labels if r['pcap'] == name]
        pcap_comparisons.extend(compare_frames(expected, rows, COMPARE_COLUMNS))
        raw_rows = [dict(pcap=name, **{BASE_FIELDS[k]: v for k, v in r.items()})
                    for r in read_csv(root / capture['raw_csv'])]
        raw_comparisons.extend(compare_frames(expected, raw_rows,
            [BASE_FIELDS[k] for k in read_csv(root / capture['raw_csv'])[0] if k != 'frame.number']))
        exported = [dict(pcap=name, **{extraction_fields[k]: v for k, v in r.items()})
                    for r in read_csv(extraction_dir / f'{scenario}_official_filter.csv')]
        expected_attacks = [dict(pcap=r['pcap'], frame_number=r['frame_number'],
            frame_time_epoch=r['frame_time_epoch'], frame_len=r['frame_len'], subtype=r['wlan_fc_type_subtype'],
            bssid=r['wlan_bssid'], capabilities=r['wlan_capabilities']) for r in attacks if r['pcap'] == name]
        filter_comparisons.extend(compare_frames(expected_attacks, exported,
            ['frame_time_epoch', 'frame_len', 'subtype', 'bssid', 'capabilities']))
        filter_counts[name] = len(exported)
    write_csv(out / 'pcap_beacon_join_audit.csv', pcap_comparisons)
    write_csv(out / 'pcap_official_filter_audit.csv', filter_comparisons)
    write_csv(out / 'raw_csv_join_audit.csv', raw_comparisons)
    coverage_ok = set(r['pcap'] for r in labels + attacks) <= set(actual_by_capture)
    scenario_lookup = {c['pcap']: c['scenario'] for c in config['captures']}
    scenarios_ok = all(r['capture_label'] == scenario_lookup[r['pcap']] for r in labels)
    attack_names_ok = all(r['attack_related_label'] == scenario_lookup[r['pcap']] for r in attacks)
    checks = dict(duplicate_labeled_keys=0, duplicate_attack_label_keys=0,
        existing_label_join_mismatches=sum(not r['agrees'] for r in join),
        pcap_beacon_mismatches=sum(not r['agrees'] for r in pcap_comparisons),
        pcap_official_filter_mismatches=sum(not r['agrees'] for r in filter_comparisons),
        raw_csv_mismatches=sum(not r['agrees'] for r in raw_comparisons),
        every_labeled_capture_inspected=coverage_ok, scenario_annotations_consistent=scenarios_ok,
        attack_scenario_labels_consistent=attack_names_ok)
    # Direct PCAP is canonical. Legacy raw CSVs are supplemental export views and
    # may omit malformed/partial records; their differences remain explicit.
    integrity = all(checks[k] == 0 for k in ['existing_label_join_mismatches',
        'pcap_beacon_mismatches', 'pcap_official_filter_mismatches']) and coverage_ok and scenarios_ok and attack_names_ok
    gate = training_gate(validated, integrity)
    write_json(out / 'training_gate.json', gate)
    distribution = Counter((r['pcap'], r['beacon_role_label'], r['identity_status'], r['attack_related_label'], r['attack_label_status']) for r in validated)
    write_csv(out / 'label_distribution.csv', [dict(pcap=k[0], legacy_role=k[1], identity_status=k[2], attack_label=k[3], attack_label_status=k[4], records=v) for k, v in sorted(distribution.items())])
    provenance = []
    for status in IDENTITY_STATUSES:
        selected = [r for r in validated if r['identity_status'] == status]
        provenance.append(dict(identity_status=status, records=len(selected),
            source=';'.join(sorted({r['identity_evidence_id'] for r in selected})),
            source_url=evidence['source_url'] if status.startswith('candidate') else '',
            independent_identity_verified=status.startswith('verified'),
            approved_as_training_target=False,
            interpretation='Author-documented candidate role, capture-specific assumption' if status.startswith('candidate') else 'No independently verified records available' if status.startswith('verified') else 'Excluded; filter non-match never converted to NORMAL'))
    write_csv(out / 'label_provenance.csv', provenance)
    features = feature_availability(actual_by_capture, labels[0].keys())
    write_csv(out / 'feature_availability.csv', features)
    actual = [r for g in actual_by_capture.values() for r in g]
    write_csv(out / 'stream_quality.csv', stream_quality(actual, config['planned_quality']['gap_factor']))
    discontinuities = temporal_discontinuities(actual)
    write_csv(out / 'temporal_discontinuities.csv', discontinuities,
        ['pcap', 'bssid', 'capabilities', 'previous_frame', 'current_frame', 'previous_epoch', 'current_epoch',
         'previous_tsf_us', 'current_tsf_us', 'delta_arrival_ns', 'delta_tsf_us', 'interpretation'])
    write_csv(out / 'configuration_shortcut_audit.csv', shortcut_profile(validated))
    overlap = previous_overlap(read_csv(root / config['prior_windows']), validated)
    write_csv(out / 'previous_time_shield_overlap.csv', overlap)
    quality_rows = []
    for r in actual:
        reasons = []
        for field in ['bssid', 'ssid_hex', 'tsf', 'capabilities', 'beacon_interval_tu']:
            if not r[field]:
                reasons.append('missing_' + field)
        if r.get('malformed'):
            reasons.append('tshark_malformed')
        if int(r['captured_len']) < int(r['frame_len']):
            reasons.append('capture_truncated')
        if reasons:
            quality_rows.append(dict(pcap=r['pcap'], frame_number=r['frame_number'], frame_len=r['frame_len'], reasons=';'.join(reasons)))
    write_csv(out / 'flagged_beacons.csv', quality_rows, ['pcap', 'frame_number', 'frame_len', 'reasons'])
    inventory = []
    for meta in extraction['captures']:
        pcap = meta['pcap']; beacons = actual_by_capture.get(pcap)
        # No inferred beacon counts for uninspected captures, including renumbered derivative.
        inventory.append(dict(**meta, beacon_count=len(beacons) if beacons is not None else '',
            beacon_count_status='full direct PCAP extraction' if beacons is not None else 'not inspected',
            exact_filter_match_count=filter_counts.get(pcap, ''),
            role='derived_subset_do_not_treat_as_independent_session' if pcap.endswith('.pcapng') else 'original_capture'))
    write_csv(out / 'full_capture_inventory.csv', inventory)
    csv_inventory = [profile_csv(p, root) for p in sorted((root / config['pcap_directory']).glob('*.csv'))]
    forbidden = [dict(field=x, eligible=False, permitted_use='grouping/provenance/validation only') for x in sorted(FORBIDDEN)]
    write_csv(out / 'forbidden_features.csv', forbidden)
    audit = dict(timestamp_utc=datetime.now(timezone.utc).isoformat(), random_seed=config['random_seed'],
        versions=dict(python=platform.python_version(), external=extraction['tshark_version'], python_dependencies='stdlib only'),
        scope='Full file inventory; direct packet-level audit of Evil_Twin and Rogue_AP only',
        labeled_beacons=len(labels), attack_label_rows=len(attacks), pcaps=inventory, csv_schemas=csv_inventory,
        checks=checks, training_gate=gate,
        unique_bssids=sorted({r['bssid'] for r in labels}), unique_ssid_hex=sorted({r['ssid_hex'] for r in labels}),
        radiotap_fields_observed={k: sum(bool(r.get(v)) for r in actual) for k, v in extraction_fields.items() if k.startswith('radiotap.')},
        tsf_fields_observed={k: sum(bool(r.get(v)) for r in actual) for k, v in extraction_fields.items() if k in ('wlan.fixed.timestamp', 'radiotap.mactime')},
        flagged_beacon_records=len(quality_rows), temporal_discontinuity_count=len(discontinuities),
        integrity_scope='Canonical labeled/attack-label tables vs original PCAP. Auxiliary raw CSV discrepancies reported separately.',
        independent_labeled_evil_twin_sessions=0, candidate_evil_twin_captures=1,
        source_evidence=evidence, config=config,
        inputs={str(p.relative_to(root)) if p.is_relative_to(root) else p.name: sha256(p) for p in
                [labels_path, attacks_path, root / config['readme'], root / config['role_builder'], root / config['prior_windows']]},
        code_sha256={p.name: sha256(p) for p in sorted(Path(__file__).parent.glob('*.py'))},
        config_sha256=sha256(config_path), evidence_sha256=sha256(evidence_path),
        extraction_manifest_sha256=sha256(extraction_dir / 'extraction_manifest.json'),
        pcap_hash_scope='Full SHA256 computed at extraction time by capinfos; immutable source assumption between extraction and audit',
        experiments=dict(models_trained=0, window_sets_built=0, metrics_computed=0, synthetic_records=0, baseline_refit=False))
    write_json(out / 'dataset_audit.json', audit)
    write_report(out, audit, evidence)
    print(json.dumps(dict(checks=checks, training_gate=gate, output=str(out)), indent=2))


def main():
    project = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, default=project / 'configs/experiment.yaml')
    p.add_argument('--dataset-root', type=Path)
    p.add_argument('--extractions', type=Path, default=project / 'data/raw/audit')
    p.add_argument('--out', type=Path, default=project / 'results/audit')
    args = p.parse_args()
    run(args.config, args.dataset_root, args.extractions, args.out)


if __name__ == '__main__':
    main()
