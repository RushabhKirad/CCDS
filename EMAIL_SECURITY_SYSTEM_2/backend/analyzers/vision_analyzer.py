import pytesseract
from PIL import Image
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VisionAnalyzer:
    """
    Vision Analyzer for Image-Based Phishing Detection.
    Uses OCR (Tesseract) to extract text from images.
    """
    
    def __init__(self):
        # Tesseract configuration (optional: set path if not in PATH)
        # pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
        pass

    def extract_text_from_image(self, image_path):
        """
        Extracts text from an image file using OCR.
        
        Args:
            image_path (str): Path to the image file.
            
        Returns:
            str: Extracted text or empty string if failed.
        """
        if not image_path or not os.path.exists(image_path):
            logger.warning(f"Image not found: {image_path}")
            return ""
            
        try:
            # Open image
            img = Image.open(image_path)
            
            # Perform OCR
            text = pytesseract.image_to_string(img)
            
            # Basic cleaning
            text = text.strip()
            
            if text:
                logger.info(f"OCR extracted {len(text)} characters from {os.path.basename(image_path)}")
            else:
                logger.info(f"OCR found no text in {os.path.basename(image_path)}")
                
            return text
            
        except Exception as e:
            logger.error(f"OCR failed for {image_path}: {e}")
            return ""

    def analyze_image(self, image_path, text_analyzer_func=None):
        """
        Analyzes an image for phishing content.
        
        Args:
            image_path (str): Path to the image.
            text_analyzer_func (callable): Function to analyze the extracted text.
                                         Should accept (text) and return (score, label).
                                         
        Returns:
            dict: Analysis results including extracted text and score.
        """
        extracted_text = self.extract_text_from_image(image_path)
        
        result = {
            "extracted_text": extracted_text,
            "has_text": bool(extracted_text),
            "ocr_score": 0.0,
            "is_suspicious": False
        }
        
        # If we have a text analyzer (e.g., the existing ML model), use it
        if extracted_text and text_analyzer_func:
            try:
                # We assume text_analyzer_func returns something we can use
                # For now, we'll just return the text for the hybrid analyzer to process
                pass
            except Exception as e:
                logger.error(f"Text analysis of OCR content failed: {e}")
        
        return result
