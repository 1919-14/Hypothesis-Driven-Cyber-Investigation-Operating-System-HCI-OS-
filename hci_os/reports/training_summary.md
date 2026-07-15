# HCI-OS A4 Model Validation Report

Validated at: `2026-07-15T03:28:09.711708+00:00Z`

## Results

| Model | Status | Key Metric | AUC |
|---|---|---|---|
| isolation_forest | ❌ FAIL | FPR=0.1478, DR=0.001 | 0.5649 |
| gaussian_likelihood | ✅ PASS | Attack/Benign Mahal ratio=3.526x | 0.7641 |
| lstm_autoencoder | ✅ PASS | Attack/Benign MSE ratio=1.665x | 0.6601 |

## Pass Bars (Unsupervised Models)
- **Isolation Forest**: FPR ≤ 0.15, DR ≥ 0.5 (ROC-optimal threshold)
- **LSTM-AE**: Attack MSE / Normal MSE ≥ 1.5× (NumPy fixed-encoder baseline)
- **Gaussian**: Attack Mahal / Normal Mahal ≥ 2.0×

## Training Details
- Isolation Forest: 2,940,723 CICIDS-2017 benign samples, n_estimators=200
- LSTM-AE: 499,991 sequences (10 timesteps × 20 features), 20 epochs, pure NumPy
- Gaussian: 200,000 benign samples, multivariate fit with regularization

## Datasets Used
- CICIDS-2017 (benign: 2.94M rows from Monday–Friday CSVs)
- CICIDS-2017 (attack: from labeled Tuesday–Friday CSVs)
- CIC-UNSW-NB15 (attack: label=1–9 per Readme.txt)