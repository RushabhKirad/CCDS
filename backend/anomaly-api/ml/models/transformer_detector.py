import torch
import torch.nn as nn
import numpy as np
import math

class TransformerAnomalyDetector(nn.Module):
    def __init__(self, input_dim: int, d_model: int = 64, nhead: int = 8, 
                 num_layers: int = 3, sequence_length: int = 10):
        super().__init__()
        self.input_dim = input_dim
        self.d_model = d_model
        self.sequence_length = sequence_length
        
        # Input projection
        self.input_projection = nn.Linear(input_dim, d_model)
        
        # Positional encoding
        self.pos_encoding = PositionalEncoding(d_model, sequence_length)
        
        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers)
        
        # Reconstruction head
        self.reconstruction_head = nn.Linear(d_model, input_dim)
        
    def forward(self, x):
        # Project to model dimension
        x = self.input_projection(x)
        
        # Add positional encoding
        x = self.pos_encoding(x)
        
        # Transformer encoding
        encoded = self.transformer(x)
        
        # Reconstruct
        reconstructed = self.reconstruction_head(encoded)
        
        return reconstructed
    
    def get_reconstruction_error(self, x):
        self.eval()
        with torch.no_grad():
            reconstructed = self.forward(x)
            mse = torch.mean((x - reconstructed) ** 2, dim=(1, 2))
        return mse

class PositionalEncoding(nn.Module):
    def __init__(self, d_model: int, max_len: int = 5000):
        super().__init__()
        
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * 
                           (-math.log(10000.0) / d_model))
        
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0).transpose(0, 1)
        
        self.register_buffer('pe', pe)
    
    def forward(self, x):
        return x + self.pe[:x.size(1), :].transpose(0, 1)