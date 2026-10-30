#!/usr/bin/env python3
"""Create diagnostic figures from frozen preliminary result tables."""
import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def main():
    project = Path(__file__).resolve().parents[1]
    results = project / 'results/preliminary_non_temporal_v1'
    figures = results / 'figures'
    if figures.exists():
        raise FileExistsError(figures)
    figures.mkdir()
    table = pd.read_csv(results / 'model_comparison.csv')
    selection = json.loads((project / 'models/preliminary_non_temporal_v1/selection_manifest.json').read_text())
    table['validation_f1'] = table.experiment_id.map(
        lambda identifier: selection['selected'][identifier]['validation_metrics']['f1'])

    labels = [f"n{row.window_size} {row.model.replace('_', ' ')}" for row in table.itertuples()]
    positions = np.arange(len(table)); width = 0.38
    fig, axis = plt.subplots(figsize=(10, 4.8))
    axis.bar(positions - width / 2, table.validation_f1, width, label='Validation F1')
    axis.bar(positions + width / 2, table.f1, width, label='Development-test F1')
    axis.set_xticks(positions, labels, rotation=25, ha='right')
    axis.set_ylim(0, 1.08); axis.set_ylabel('F1 (candidate Evil Twin)')
    axis.set_title('Preliminary same-capture results — not independent evaluation')
    axis.legend(); fig.tight_layout()
    fig.savefig(figures / 'model_comparison.png', dpi=180); plt.close(fig)

    fig, axes = plt.subplots(2, 3, figsize=(10, 6.5))
    for axis, row in zip(axes.flat, table.itertuples()):
        matrix = np.array([[row.tn, row.fp], [row.fn, row.tp]])
        axis.imshow(matrix, cmap='Blues', vmin=0, vmax=matrix.max())
        for (i, j), value in np.ndenumerate(matrix):
            axis.text(j, i, str(value), ha='center', va='center')
        axis.set_title(f'n{row.window_size} {row.model.replace("_", " ")}')
        axis.set_xticks([0, 1], ['Legit', 'Evil']); axis.set_yticks([0, 1], ['Legit', 'Evil'])
        axis.set_xlabel('Predicted'); axis.set_ylabel('Candidate label')
    fig.suptitle('Development-test confusion matrices (same original capture)')
    fig.tight_layout(); fig.savefig(figures / 'confusion_matrices.png', dpi=180); plt.close(fig)


if __name__ == '__main__':
    main()
