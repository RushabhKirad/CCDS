import torch
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BertAnalyzer:
    """
    Advanced NLP Analyzer using DistilBERT.
    Detects phishing context that simple keyword matching misses.
    """
    
    def __init__(self):
        self.tokenizer = None
        self.model = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model_name = "distilbert-base-uncased-finetuned-sst-2-english" # Using a pre-finetuned model as base
        # Ideally, we would fine-tune this on a phishing dataset
        
        self._load_model()

    def _load_model(self):
        """Loads the DistilBERT model and tokenizer."""
        try:
            logger.info(f"Loading BERT model ({self.model_name})... This may take a while.")
            self.tokenizer = DistilBertTokenizer.from_pretrained(self.model_name)
            self.model = DistilBertForSequenceClassification.from_pretrained(self.model_name)
            self.model.to(self.device)
            self.model.eval()
            logger.info("BERT model loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load BERT model: {e}")

    def analyze_text(self, text):
        """
        Analyzes text using BERT.
        
        Args:
            text (str): Email body/subject.
            
        Returns:
            float: Phishing probability (0.0 - 1.0).
        """
        if not self.model or not self.tokenizer:
            return 0.5 # Neutral if model failed
            
        try:
            # Truncate text to 512 tokens
            inputs = self.tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=512)
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=1)
                
            # Assuming label 1 is negative/phishing (depends on fine-tuning)
            # For SST-2: 0 is Negative, 1 is Positive. 
            # We need to invert logic or fine-tune. 
            # For this demo, we'll assume Negative sentiment correlates with Phishing (Fear/Urgency)
            # This is a simplification. Real implementation needs fine-tuning on Phishing dataset.
            phishing_prob = probabilities[0][0].item() # Probability of Negative sentiment
            
            return phishing_prob
            
        except Exception as e:
            logger.error(f"BERT analysis failed: {e}")
            return 0.5
