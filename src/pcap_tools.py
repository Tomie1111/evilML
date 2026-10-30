"""Bounded-memory PCAP inspection using the installed Wireshark CLI."""
import csv
import io
import shutil
import subprocess
from pathlib import Path

BASE_FIELDS = {
    'frame.number': 'frame_number', 'frame.time_epoch': 'frame_time_epoch',
    'frame.len': 'frame_len', 'frame.cap_len': 'captured_len',
    'wlan.fc.type_subtype': 'subtype', 'wlan.bssid': 'bssid', 'wlan.sa': 'source_mac',
    'wlan.ta': 'transmitter_mac', 'wlan.addr': 'wlan_addresses', 'ip.addr': 'ip_addresses',
    'wlan.fc.protected': 'protected', 'wlan.fc.retry': 'retry',
    'wlan.ssid': 'ssid_hex', 'wlan.fixed.timestamp': 'tsf',
    'wlan.fixed.beacon': 'beacon_interval_tu', 'wlan.fixed.capabilities': 'capabilities',
    'wlan.seq': 'sequence_number', 'wlan.tag.number': 'ie_tag_ids',
    'wlan.rsn.version': 'rsn_version', 'radiotap.dbm_antsignal': 'radiotap_rssi_dbm',
    'radiotap.channel.freq': 'radiotap_channel_freq',
}
EXTRA_FIELDS = {
    'wlan.rsn.capabilities': 'rsn_capabilities', 'wlan.rsn.gcs.type': 'group_cipher',
    'wlan.rsn.pcs.type': 'pairwise_ciphers', 'wlan.rsn.akms.type': 'akm_suites',
    'wlan.supported_rates': 'supported_rates',
    'wlan.extended_supported_rates': 'extended_supported_rates',
    'radiotap.mactime': 'radiotap_tsft', 'radiotap.antenna': 'radiotap_antenna',
    'radiotap.dbm_antnoise': 'radiotap_noise_dbm', 'wlan.fcs.status': 'fcs_status',
    '_ws.malformed': 'malformed',
}


def find_tool(name, explicit=None):
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            raise FileNotFoundError(p)
        return str(p.resolve())
    found = shutil.which(name)
    if found:
        return found
    p = Path('/Applications/Wireshark.app/Contents/MacOS') / name
    if p.is_file():
        return str(p)
    raise FileNotFoundError(f'{name} not found; set its path in config')


def field_registry(tshark):
    result = subprocess.run([tshark, '-G', 'fields'], capture_output=True, text=True, check=True)
    return {v[2]: v[3] for line in result.stdout.splitlines()
            if len(v := line.split('\t')) > 3 and v[0] == 'F'}


def pcap_info(capinfos, path):
    result = subprocess.run([capinfos, '-T', '-m', '-Q', '-c', '-s', '-a', '-e', '-o', '-E', '-H', '-S', str(path)],
                            capture_output=True, text=True, check=True)
    records = list(csv.DictReader(io.StringIO(result.stdout)))
    if len(records) != 1:
        raise ValueError(f'Unexpected capinfos output: {path}')
    r = records[0]
    return dict(total_frames=int(r['Number of packets']), bytes=int(r['File size (bytes)']),
                first_epoch=r['Start time'], last_epoch=r['End time'],
                sha256=r['SHA256'], encapsulation=r['File encapsulation'],
                strict_time_order=r['Strict time order'], warnings=result.stderr.strip())


def read_official_filter(readme, scenario):
    lines = Path(readme).read_text().splitlines()
    for i, line in enumerate(lines):
        if line.strip() == scenario:
            return next(v.strip() for v in lines[i + 1:] if v.strip())
    raise ValueError(f'No documented filter for {scenario}')


def stream_extract(tshark, pcap, display_filter, fields, destination, log):
    """TShark writes directly to disk; subprocess output never contains a PCAP in RAM."""
    cmd = [tshark, '-n', '-o', 'wlan.enable_decryption:FALSE', '-r', str(pcap),
           '-Y', display_filter, '-T', 'fields', '-E', 'header=y', '-E', 'separator=,',
           '-E', 'quote=d', '-E', 'occurrence=a', '-E', 'aggregator=;']
    for field in fields:
        cmd += ['-e', field]
    with Path(destination).open('w') as output, Path(log).open('w') as error:
        result = subprocess.run(cmd, stdout=output, stderr=error)
    if result.returncode:
        raise RuntimeError(f'TShark failed ({result.returncode}); see {log}')
    return cmd


def filter_matches(scenario, r):
    """Reconstruct the locally documented filter; exact TShark replay also checked separately."""
    n = int(r['frame_number']); subtype = int(r['subtype'], 0)
    if scenario == 'Rogue_AP':
        return subtype == 8 and 1198551 <= n <= 1973111 and int(r['frame_len']) < 264
    if scenario != 'Evil_Twin':
        raise ValueError(scenario)
    kind = (subtype == 8 and int(r['frame_len']) < 242) or (
        subtype in (10, 12, 40) and r['protected'] in ('0', 'False'))
    address = '192.168.30.1' in r['ip_addresses'].split(';') or '0c:9d:92:54:fe:35' in r['wlan_addresses'].lower().split(';')
    return bool(kind and 1420038 <= n <= 3778728 and address)
