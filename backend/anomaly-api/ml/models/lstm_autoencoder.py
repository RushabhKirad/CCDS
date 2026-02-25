import torch
import torch.nn as nn
import numpy as np
from typing import Tuple, Optional

class LSTMAutoencoder(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int = 64, num_layers: int = 2, 
                 sequence_length: int = 10, dropout: float = 0.2):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.sequence_length = sequence_length
        
        # Encoder
        self.encoder_lstm = nn.LSTM(input_dim, hidden_dim, num_layers, 
                                   batch_first=True, dropout=dropout)
        
        # Decoder
        self.decoder_lstm = nn.LSTM(hidden_dim, hidden_dim, num_layers, 
                                   batch_first=True, dropout=dropout)
        self.output_layer = nn.Linear(hidden_dim, input_dim)
        
    def encode(self, x: torch.Tensor) -> Tuple[torch.Tensor, Tuple]:
        encoded, hidden = self.encoder_lstm(x)
        return encoded[:, -1, :].unsqueeze(1), hidden
    
    def decode(self, encoded: torch.Tensor, target_length: int) -> torch.Tensor:
        batch_size = encoded.size(0)
        decoded = torch.zeros(batch_size, target_length, self.hidden_dim, device=encoded.device)
        
        hidden = None
        input_seq = encoded
        
        for i in range(target_length):
            output, hidden = self.decoder_lstm(input_seq, hidden)
            decoded[:, i:i+1, :] = output
            input_seq = output
            
        return self.output_layer(decoded)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        encoded, _ = self.encode(x)
        decoded = self.decode(encoded, x.size(1))
        return decoded
    
    def get_reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        self.eval()
        with torch.no_grad():
            reconstructed = self.forward(x)
            mse = torch.mean((x - reconstructed) ** 2, dim=(1, 2))
        return mse
    
    def predict_anomaly_scores(self, x: torch.Tensor, threshold: Optional[float] = None) -> np.ndarray:
        errors = self.get_reconstruction_error(x)
        scores = errors.cpu().numpy()
        
        if threshold is not None:
            return (scores > threshold).astype(int)
        return scores