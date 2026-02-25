#!/usr/bin/env python3
"""
Advanced Deep Learning Models for Cyber Defense
State-of-the-art neural networks for anomaly detection
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdvancedLSTMAutoencoder(nn.Module):
    """Advanced LSTM Autoencoder with attention mechanism"""
    
    def __init__(self, input_size=100, hidden_size=128, num_layers=3, dropout=0.2):
        super(AdvancedLSTMAutoencoder, self).__init__()
        
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        
        # Encoder
        self.encoder_lstm = nn.LSTM(
            input_size, hidden_size, num_layers,
            batch_first=True, dropout=dropout, bidirectional=True
        )
        
        # Attention mechanism
        self.attention = nn.MultiheadAttention(
            embed_dim=hidden_size * 2,
            num_heads=8,
            dropout=dropout,
            batch_first=True
        )
        
        # Bottleneck
        self.bottleneck = nn.Sequential(
            nn.Linear(hidden_size * 2, hidden_size),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Linear(hidden_size // 2, hidden_size),
            nn.ReLU()
        )
        
        # Decoder
        self.decoder_lstm = nn.LSTM(
            hidden_size, hidden_size, num_layers,
            batch_first=True, dropout=dropout
        )
        
        self.output_layer = nn.Linear(hidden_size, input_size)
        
    def forward(self, x):
        batch_size, seq_len, _ = x.shape
        
        # Encode
        encoded, (h_n, c_n) = self.encoder_lstm(x)
        
        # Apply attention
        attended, _ = self.attention(encoded, encoded, encoded)
        
        # Bottleneck
        bottleneck_out = self.bottleneck(attended)
        
        # Decode
        decoded, _ = self.decoder_lstm(bottleneck_out)
        
        # Output
        reconstructed = self.output_layer(decoded)
        
        return reconstructed
    
    def get_reconstruction_error(self, x):
        self.eval()
        with torch.no_grad():
            reconstructed = self.forward(x)
            mse = torch.mean((x - reconstructed) ** 2, dim=(1, 2))
            return mse

class TransformerAnomalyDetector(nn.Module):
    """Transformer-based anomaly detection model"""
    
    def __init__(self, input_size=100, d_model=256, nhead=8, num_layers=6, dropout=0.1):
        super(TransformerAnomalyDetector, self).__init__()
        
        self.input_size = input_size
        self.d_model = d_model
        
        # Input projection
        self.input_projection = nn.Linear(input_size, d_model)
        
        # Positional encoding
        self.pos_encoding = PositionalEncoding(d_model, dropout)
        
        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=d_model * 4,
            dropout=dropout,
            activation='gelu',
            batch_first=True
        )
        
        self.transformer_encoder = nn.TransformerEncoder(
            encoder_layer, num_layers=num_layers
        )
        
        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 2, d_model // 4),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 4, 1),
            nn.Sigmoid()
        )
        
    def forward(self, x):
        # Project input
        x = self.input_projection(x)
        
        # Add positional encoding
        x = self.pos_encoding(x)
        
        # Transformer encoding
        encoded = self.transformer_encoder(x)
        
        # Global average pooling
        pooled = torch.mean(encoded, dim=1)
        
        # Classification
        output = self.classifier(pooled)
        
        return output.squeeze(-1)

class PositionalEncoding(nn.Module):
    """Positional encoding for transformer"""
    
    def __init__(self, d_model, dropout=0.1, max_len=5000):
        super(PositionalEncoding, self).__init__()
        self.dropout = nn.Dropout(p=dropout)
        
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * 
                           (-np.log(10000.0) / d_model))
        
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0).transpose(0, 1)
        
        self.register_buffer('pe', pe)
        
    def forward(self, x):
        x = x + self.pe[:x.size(1), :].transpose(0, 1)
        return self.dropout(x)

class ConvolutionalAnomalyDetector(nn.Module):
    """1D CNN for pattern detection in network features"""
    
    def __init__(self, input_size=100, num_filters=64, dropout=0.2):
        super(ConvolutionalAnomalyDetector, self).__init__()
        
        # Multi-scale convolutional layers
        self.conv1 = nn.Conv1d(1, num_filters, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(num_filters, num_filters * 2, kernel_size=5, padding=2)
        self.conv3 = nn.Conv1d(num_filters * 2, num_filters * 4, kernel_size=7, padding=3)
        
        # Batch normalization
        self.bn1 = nn.BatchNorm1d(num_filters)
        self.bn2 = nn.BatchNorm1d(num_filters * 2)
        self.bn3 = nn.BatchNorm1d(num_filters * 4)
        
        # Dropout
        self.dropout = nn.Dropout(dropout)
        
        # Global pooling
        self.global_pool = nn.AdaptiveAvgPool1d(1)
        
        # Classification layers
        self.classifier = nn.Sequential(
            nn.Linear(num_filters * 4, num_filters * 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(num_filters * 2, num_filters),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(num_filters, 1),
            nn.Sigmoid()
        )
        
    def forward(self, x):
        # Reshape for 1D convolution
        if len(x.shape) == 3:
            x = x.view(x.size(0), 1, -1)  # (batch, 1, features)
        elif len(x.shape) == 2:
            x = x.unsqueeze(1)  # (batch, 1, features)
        
        # Convolutional layers
        x = F.relu(self.bn1(self.conv1(x)))
        x = self.dropout(x)
        
        x = F.relu(self.bn2(self.conv2(x)))
        x = self.dropout(x)
        
        x = F.relu(self.bn3(self.conv3(x)))
        x = self.dropout(x)
        
        # Global pooling
        x = self.global_pool(x)
        x = x.view(x.size(0), -1)
        
        # Classification
        output = self.classifier(x)
        
        return output.squeeze(-1)

class VariationalAutoencoder(nn.Module):
    """Variational Autoencoder for anomaly detection"""
    
    def __init__(self, input_size=100, latent_size=32, hidden_size=256):
        super(VariationalAutoencoder, self).__init__()
        
        self.input_size = input_size
        self.latent_size = latent_size
        
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_size, hidden_size),
            nn.ReLU(),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Linear(hidden_size // 2, hidden_size // 4),
            nn.ReLU()
        )
        
        # Latent space
        self.mu_layer = nn.Linear(hidden_size // 4, latent_size)
        self.logvar_layer = nn.Linear(hidden_size // 4, latent_size)
        
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_size, hidden_size // 4),
            nn.ReLU(),
            nn.Linear(hidden_size // 4, hidden_size // 2),
            nn.ReLU(),
            nn.Linear(hidden_size // 2, hidden_size),
            nn.ReLU(),
            nn.Linear(hidden_size, input_size)
        )
        
    def encode(self, x):
        h = self.encoder(x)
        mu = self.mu_layer(h)
        logvar = self.logvar_layer(h)
        return mu, logvar
    
    def reparameterize(self, mu, logvar):
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std
    
    def decode(self, z):
        return self.decoder(z)
    
    def forward(self, x):
        mu, logvar = self.encode(x)
        z = self.reparameterize(mu, logvar)
        reconstructed = self.decode(z)
        return reconstructed, mu, logvar
    
    def get_anomaly_score(self, x):
        self.eval()
        with torch.no_grad():
            reconstructed, mu, logvar = self.forward(x)
            
            # Reconstruction loss
            recon_loss = F.mse_loss(reconstructed, x, reduction='none').sum(dim=1)
            
            # KL divergence
            kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp(), dim=1)
            
            # Total anomaly score
            anomaly_score = recon_loss + 0.1 * kl_loss
            
            return anomaly_score

class EnsembleAnomalyDetector(nn.Module):
    """Ensemble of multiple deep learning models"""
    
    def __init__(self, input_size=100, sequence_length=10):
        super(EnsembleAnomalyDetector, self).__init__()
        
        self.input_size = input_size
        self.sequence_length = sequence_length
        
        # Individual models
        self.lstm_autoencoder = AdvancedLSTMAutoencoder(input_size)
        self.transformer = TransformerAnomalyDetector(input_size)
        self.cnn = ConvolutionalAnomalyDetector(input_size)
        self.vae = VariationalAutoencoder(input_size)
        
        # Ensemble fusion layer
        self.fusion = nn.Sequential(
            nn.Linear(4, 8),  # 4 model outputs
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(8, 4),
            nn.ReLU(),
            nn.Linear(4, 1),
            nn.Sigmoid()
        )
        
    def forward(self, x):
        batch_size = x.size(0)
        
        # Prepare inputs for different models
        if len(x.shape) == 2:
            # Single features, create sequences
            x_seq = x.unsqueeze(1).repeat(1, self.sequence_length, 1)
        else:
            x_seq = x
        
        x_flat = x.view(batch_size, -1) if len(x.shape) > 2 else x
        
        # Get predictions from each model
        lstm_error = self.lstm_autoencoder.get_reconstruction_error(x_seq)
        transformer_pred = self.transformer(x_seq)
        cnn_pred = self.cnn(x_flat)
        vae_score = self.vae.get_anomaly_score(x_flat)
        
        # Normalize scores
        lstm_norm = torch.sigmoid(lstm_error)
        vae_norm = torch.sigmoid(vae_score)
        
        # Stack predictions
        ensemble_input = torch.stack([
            lstm_norm, transformer_pred, cnn_pred, vae_norm
        ], dim=1)
        
        # Fusion
        ensemble_output = self.fusion(ensemble_input)
        
        return ensemble_output.squeeze(-1)
    
    def get_individual_predictions(self, x):
        """Get predictions from individual models"""
        batch_size = x.size(0)
        
        if len(x.shape) == 2:
            x_seq = x.unsqueeze(1).repeat(1, self.sequence_length, 1)
        else:
            x_seq = x
        
        x_flat = x.view(batch_size, -1) if len(x.shape) > 2 else x
        
        with torch.no_grad():
            lstm_error = self.lstm_autoencoder.get_reconstruction_error(x_seq)
            transformer_pred = self.transformer(x_seq)
            cnn_pred = self.cnn(x_flat)
            vae_score = self.vae.get_anomaly_score(x_flat)
        
        return {
            'lstm': torch.sigmoid(lstm_error),
            'transformer': transformer_pred,
            'cnn': cnn_pred,
            'vae': torch.sigmoid(vae_score)
        }

class FocalLoss(nn.Module):
    """Focal Loss for handling class imbalance"""
    
    def __init__(self, alpha=1, gamma=2):
        super(FocalLoss, self).__init__()
        self.alpha = alpha
        self.gamma = gamma
        
    def forward(self, inputs, targets):
        ce_loss = F.binary_cross_entropy(inputs, targets, reduction='none')
        pt = torch.exp(-ce_loss)
        focal_loss = self.alpha * (1 - pt) ** self.gamma * ce_loss
        return focal_loss.mean()

def test_advanced_models():
    """Test advanced deep learning models"""
    
    print("Testing Advanced Deep Learning Models")
    print("=" * 40)
    
    # Test data
    batch_size = 32
    input_size = 100
    sequence_length = 10
    
    # Create test data
    x_features = torch.randn(batch_size, input_size)
    x_sequences = torch.randn(batch_size, sequence_length, input_size)
    y_labels = torch.randint(0, 2, (batch_size,)).float()
    
    print(f"Test data shapes:")
    print(f"  Features: {x_features.shape}")
    print(f"  Sequences: {x_sequences.shape}")
    print(f"  Labels: {y_labels.shape}")
    
    # Test individual models
    print(f"\nTesting individual models...")
    
    # LSTM Autoencoder
    lstm_model = AdvancedLSTMAutoencoder(input_size)
    lstm_output = lstm_model(x_sequences)
    lstm_errors = lstm_model.get_reconstruction_error(x_sequences)
    print(f"LSTM Autoencoder - Output: {lstm_output.shape}, Errors: {lstm_errors.shape}")
    
    # Transformer
    transformer_model = TransformerAnomalyDetector(input_size)
    transformer_output = transformer_model(x_sequences)
    print(f"Transformer - Output: {transformer_output.shape}")
    
    # CNN
    cnn_model = ConvolutionalAnomalyDetector(input_size)
    cnn_output = cnn_model(x_features)
    print(f"CNN - Output: {cnn_output.shape}")
    
    # VAE
    vae_model = VariationalAutoencoder(input_size)
    vae_recon, vae_mu, vae_logvar = vae_model(x_features)
    vae_scores = vae_model.get_anomaly_score(x_features)
    print(f"VAE - Reconstruction: {vae_recon.shape}, Scores: {vae_scores.shape}")
    
    # Ensemble model
    print(f"\nTesting ensemble model...")
    ensemble_model = EnsembleAnomalyDetector(input_size, sequence_length)
    ensemble_output = ensemble_model(x_features)
    individual_preds = ensemble_model.get_individual_predictions(x_features)
    
    print(f"Ensemble - Output: {ensemble_output.shape}")
    print(f"Individual predictions:")
    for model_name, pred in individual_preds.items():
        print(f"  {model_name}: {pred.shape}, mean: {pred.mean():.3f}")
    
    # Test loss function
    focal_loss = FocalLoss()
    loss_value = focal_loss(ensemble_output, y_labels)
    print(f"\nFocal Loss: {loss_value.item():.4f}")
    
    print(f"\nAdvanced model testing completed!")

if __name__ == "__main__":
    test_advanced_models()