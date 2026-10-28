# Layer 2 Leakage and Generalization Audit

## 1. Purpose

This audit reproduces the exact train/validation/test split used by the Layer 2 Transformer and checks duplicate isolation, sampled near-duplicate similarity, sender/recipient overlap, label consistency, channel distribution, and temporal coverage.

## 2. Dataset

- Total processed messages: 56,169
- Exact duplicate text rows: 410
- Exact duplicate text groups: 138
- Label 0: legitimate
- Label 1: phishing

## 3. Exact Training Split Reproduction

- Train: 39,313
- Validation: 8,404
- Test: 8,452
- Random seed: 42
- First split: 70% train / 30% held-out
- Second split: 50% validation / 50% test from held-out data
- Stratification: enabled when both labels have at least two groups
- Grouping: normalized Layer 2 message text

The split implementation reproduces the logic in `src/layer2_nlp/transformer_classifier.py`.

## 4. Exact Duplicate Isolation

- Train/Test overlap: 0
- Train/Validation overlap: 0
- Validation/Test overlap: 0

Because the training split groups identical normalized messages together, exact duplicate groups should remain isolated between partitions.

## 5. Near-Duplicate Analysis

- Method: sampled token-set Jaccard similarity
- Threshold: 0.85
- Maximum sample per split: 500
- Sampled Train/Test near-duplicates: 31
- Sampled Train/Validation near-duplicates: 31
- Sampled Validation/Test near-duplicates: 35

### Train/Test Examples

- `email_598359ba34d50081010a5dfe` ↔ `email_0655ff186164873627c7e665` | channel=EMAIL | similarity=0.9905
- `email_d879708ae08868559b48b1dd` ↔ `email_0655ff186164873627c7e665` | channel=EMAIL | similarity=0.9905
- `email_705ae7f7d83ebf0ee6304f88` ↔ `email_bf51f0cc065d54860fb7a01c` | channel=EMAIL | similarity=0.875
- `email_54ff9da63d8b1a6ab392d421` ↔ `email_0655ff186164873627c7e665` | channel=EMAIL | similarity=0.9905
- `email_ddcd2630e3889e1873965133` ↔ `email_0655ff186164873627c7e665` | channel=EMAIL | similarity=0.9905
- `email_b6e6e8d0ac63e2c8e960e69d` ↔ `email_44835adf3524250abbc9bf4f` | channel=EMAIL | similarity=0.9912
- `email_199bd3863f0ec3caf539d37f` ↔ `email_721e72ebf24ed373cf3369d5` | channel=EMAIL | similarity=0.8986
- `email_0c7c9eaf7df8179b07a09006` ↔ `email_0655ff186164873627c7e665` | channel=EMAIL | similarity=0.9905
- `email_086cc4e2f94092edfb5c904d` ↔ `email_44835adf3524250abbc9bf4f` | channel=EMAIL | similarity=0.9912
- `email_45911921ed99984df9d2bc82` ↔ `email_0655ff186164873627c7e665` | channel=EMAIL | similarity=0.9905

### Train/Validation Examples

- `email_598359ba34d50081010a5dfe` ↔ `email_517d6f615cb1058c8d430514` | channel=EMAIL | similarity=0.9905
- `email_d879708ae08868559b48b1dd` ↔ `email_517d6f615cb1058c8d430514` | channel=EMAIL | similarity=0.9905
- `email_54ff9da63d8b1a6ab392d421` ↔ `email_517d6f615cb1058c8d430514` | channel=EMAIL | similarity=0.9905
- `email_ddcd2630e3889e1873965133` ↔ `email_517d6f615cb1058c8d430514` | channel=EMAIL | similarity=0.9905
- `email_b6e6e8d0ac63e2c8e960e69d` ↔ `email_dfa7f0b0b60be89a8b739a3c` | channel=EMAIL | similarity=0.9912
- `email_0c7c9eaf7df8179b07a09006` ↔ `email_517d6f615cb1058c8d430514` | channel=EMAIL | similarity=0.9905
- `email_086cc4e2f94092edfb5c904d` ↔ `email_dfa7f0b0b60be89a8b739a3c` | channel=EMAIL | similarity=0.9912
- `email_ebb63b0fcd61684e35ad51a3` ↔ `email_c6593cd59a8315f0d101fe48` | channel=EMAIL | similarity=0.8889
- `email_45911921ed99984df9d2bc82` ↔ `email_517d6f615cb1058c8d430514` | channel=EMAIL | similarity=0.9905
- `email_a28a130513b6b92a0e85e665` ↔ `email_dfa7f0b0b60be89a8b739a3c` | channel=EMAIL | similarity=0.9912

### Validation/Test Examples

- `email_517d6f615cb1058c8d430514` ↔ `email_0655ff186164873627c7e665` | channel=EMAIL | similarity=0.9905
- `email_566c673210fb32031d031d8e` ↔ `email_0655ff186164873627c7e665` | channel=EMAIL | similarity=0.9905
- `email_f65b1ce2a547a513f87cc198` ↔ `email_0655ff186164873627c7e665` | channel=EMAIL | similarity=0.9905
- `email_6f2186a03c9ac3a957b09915` ↔ `email_decba8ea368cfc5d41996f08` | channel=EMAIL | similarity=0.9905
- `email_a9d00641e8dac4452dfd6cd2` ↔ `email_2e458405efb7d8e1151313ff` | channel=EMAIL | similarity=0.9437
- `email_158dad0a91e6075fbc06fcef` ↔ `email_0655ff186164873627c7e665` | channel=EMAIL | similarity=0.9905
- `email_2681e05e40a9b630eb4b6924` ↔ `email_0655ff186164873627c7e665` | channel=EMAIL | similarity=0.9905
- `email_51f63261965b72c652fc4f3e` ↔ `email_057a9811071df13fc797bacf` | channel=EMAIL | similarity=0.8667
- `email_dfa7f0b0b60be89a8b739a3c` ↔ `email_44835adf3524250abbc9bf4f` | channel=EMAIL | similarity=0.9912
- `email_a735aba656568894908cca5d` ↔ `email_decba8ea368cfc5d41996f08` | channel=EMAIL | similarity=0.9905

## 6. Email Sender Overlap

- Unique train senders: 21,763
- Unique validation senders: 5,429
- Unique test senders: 5,393
- Train/Test sender overlap: 1,284
- Train/Validation sender overlap: 1,302
- Validation/Test sender overlap: 694

## 7. Email Recipient Overlap

- Unique train recipients: 4,865
- Unique validation recipients: 1,795
- Unique test recipients: 1,773
- Train/Test recipient overlap: 1,179
- Train/Validation recipient overlap: 1,142
- Validation/Test recipient overlap: 691

## 8. Channel Distribution

### train
- EMAIL: 33,875
- SMS: 5,438

### validation
- EMAIL: 7,205
- SMS: 1,199

### test
- EMAIL: 7,209
- SMS: 1,243

## 9. Label Distribution

### train
- legitimate: 18,908
- phishing: 20,405

### validation
- legitimate: 4,052
- phishing: 4,352

### test
- legitimate: 4,047
- phishing: 4,405

## 10. Sender Label Consistency

- Email senders associated with both labels: 5

## 11. Temporal Coverage

- Train: 1980-01-03 10:02:05+00:00 → 2100-05-26 03:43:02+00:00
- Validation: 1980-01-04 05:39:00+00:00 → 2020-06-19 22:30:58+00:00
- Test: 1980-01-04 11:05:08+00:00 → 2100-05-27 19:54:05+00:00

## 12. Test Prediction Artifact

- Prediction file found: `D:\Mohan\cloud project 6th sem\adaptive-phishing-detection\models\phishing_classifier\test_predictions.csv`
- Prediction rows: 8,452
- Exact test split rows: 8,452
- Prediction row count matches the reproduced test split.

## 13. Interpretation

The train/validation/test split in this audit reproduces the grouping and stratified splitting logic used by the Layer 2 training implementation.

Exact normalized-message groups are isolated between partitions. Therefore, identical messages are not intentionally placed into different partitions.

Sampled near-duplicate matches can still occur because different messages may share common templates or campaign wording. These matches are not automatically proof of leakage.

Sender and recipient overlap is reported descriptively. It is not automatically classified as leakage because the Layer 2 model input does not include sender or recipient identity.

The resulting evaluation should still be interpreted as performance on this dataset distribution. It does not by itself establish performance on future or previously unseen phishing campaigns.

## 14. URL Exclusion

URLs are not used as detection features, reputation signals, domain features, WHOIS information, or model inputs.