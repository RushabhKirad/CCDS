# Algorithm & Technology Specification: Cognitive Fusion Framework

This document details the core algorithm and technological architecture of the **Cognitive Email Defense Framework (CEDF)**.

## 1. The Cognitive Fusion Algorithm (CFA)

The system operates on an **Ensemble-based Multi-Modal Intelligence** algorithm. It does not rely on a single ML model; instead, it aggregates scores from multiple "sensory modules."

### Algorithm Workflow (Pseudocode):
```text
ALGORITHM PhishingDetection(Email Input E)
  1. INITIALIZE total_threat_score = 0
  2. EXTRACT Modalities:
     a. T = Text Content (Subject + Body)
     b. U = All extracted URLs
     c. A = Attachments (if any)
     d. H = Email Headers (SPF, DKIM)

  3. ANALYZE Modality 1: VISUAL (OCR)
     - If A is Image: Extract text O_text via Tesseract-OCR
     - T = T + O_text

  4. ANALYZE Modality 2: CONTEXTUAL (NLP/BERT)
     - Score_T = (BERT_Score(T) * 0.7) + (Regex_Risk_Score(T) * 0.3)

  5. ANALYZE Modality 3: NETWORK (URL)
     - For each url in U:
         Score_U = max(ML_Url_Score, Shannon_Entropy_Score, SSL_Auth_Status)
     - Normalize Score_U

  6. ANALYZE Modality 4: STRUCTURE (Attachment)
     - Score_A = ML_RandomForest_Score(PDF_Features(A))

  7. ADAPTIVE FUSION:
     - Final_Score = (Score_T * w1) + (Score_U * w2) + (Score_A * w3) + Header_Penalty
     - (Weights w1, w2, w3 adjust dynamically based on available data)

  8. CLASSIFY:
     - If Final_Score > threshold: RETURN "PHISHING"
     - Else: RETURN "SAFE"
END
```

## 2. Theoretical Pillars
To make this paper-ready, we emphasize these three theories:
1.  **Shannon Entropy (Information Theory)**: Used to identify random data sequences in URLs.
2.  **Contextual Embeddings (Transformer Theory)**: Used via BERT to understand the hidden malicious intent in neutral-looking sentences.
3.  **Sensory Fusion Theory**: The principle that multi-modal evidence (Vision + Text) reduces the "False Positive" rate significantly compared to uni-modal systems.

## 3. Technology Stack (Implementation)
| Component | Technology Used | Rationale |
| :--- | :--- | :--- |
| **Backend** | Python / Flask | Rapid prototyping and extensive ML library support. |
| **NLP Engine** | DistilBERT / Scikit-Learn | State-of-the-art contextual understanding. |
| **Vision Engine** | Tesseract-OCR / PIL | Robust text extraction from images. |
| **URL Analysis** | python-whois / Socket | Deep network-layer verification (SSL/Domain Age). |
| **Database** | MySQL | Structured storage for email patterns and user feedback. |
| **Visualization** | Chart.js / Flask-Standalone | Real-time performance and ablation study tracking. |

## 4. Academic novelty summary
Most existing research focuses on **static analysis** of text or **blacklisting** of URLs. Our approach's novelty lies in the **Vision-augmented NLP Loop**, where OCR results are treated as primary textual evidence, enabling the detection of "Image-only" phishing attacks that bypass standard filters.
