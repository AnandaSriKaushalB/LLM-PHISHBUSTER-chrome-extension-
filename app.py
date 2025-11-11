# ========== Import necessary libraries ==========
import os  # Operating system utilities (file paths, env vars)
import random  # Random number generation for dataset and shuffling
import numpy as np  # Numerical operations and arrays
import torch  # PyTorch main library for tensors and neural nets
import torch.nn as nn  # Neural network layers and modules
import torch.optim as optim  # Optimizers like Adam, SGD
from sentence_transformers import SentenceTransformer  # Pretrained sentence embedding models
import pandas as pd  # DataFrame handling and tabular data utilities
import re  # Regular expressions for text matching
from flask import Flask, request, jsonify  # Flask web framework and helpers for APIs
from flask_cors import CORS  # CORS support for cross-origin API calls
from sklearn.model_selection import train_test_split  # Train/test dataset splitting
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score  # Evaluation metrics
import warnings  # Warnings filter

warnings.filterwarnings('ignore')  # Suppress non-critical warnings to keep logs clean

SEED = 42  # Deterministic seed for reproducibility across random modules
random.seed(SEED)  # Seed Python's random module
np.random.seed(SEED)  # Seed NumPy's RNG
torch.manual_seed(SEED)  # Seed PyTorch CPU RNG
torch.cuda.manual_seed_all(SEED)  # Seed all CUDA GPUs (if available)

app = Flask(__name__)  # Create Flask application instance
CORS(app)  # Enable Cross-Origin Resource Sharing for the Flask app

# ===============================================================
# ========== Custom synthetic dataset generator for emails ==========
# ===============================================================
class EnhancedPhishingDataset:
    def __init__(self):
        # common words often found in phishing emails; used to craft templates
        self.phishing_patterns = [
            "urgent", "verify", "suspend", "click here", "limited time", "act now",
            "confirm", "update", "login", "security alert"
        ]

    def generate_dataset(self, n_samples=2000):
        # phishing email templates with placeholders to generate synthetic phishing emails
        phishing_templates = [
            {"subject": "URGENT: Your {service} account will be suspended",
             "body": "Suspicious activity. Click here to verify: {url}",
             "service": ["PayPal", "Amazon", "Netflix", "Bank", "Apple"]},
            {"subject": "Security Alert: Unusual login detected from {location}",
             "body": "Access attempt from {location}. Confirm identity now: {url}",
             "service": ["Gmail", "Facebook", "Microsoft", "Instagram"]},
            {"subject": "Action Required: Verify your {service} payment information",
             "body": "Payment failed. Update billing info ASAP: {url}",
             "service": ["Netflix", "Spotify", "Adobe", "PayPal"]},
            {"subject": "Your package delivery failed",
             "body": "Delivery failed. Click to reschedule: {url}",
             "service": ["FedEx", "UPS", "USPS", "DHL"]},
            {"subject": "FINAL NOTICE: Account suspension imminent",
             "body": "Verify before permanent suspension: {url}",
             "service": ["Bank", "PayPal", "Amazon"]} 
        ]
        # legitimate (non-phishing) email templates to simulate real emails
        legitimate_templates = [
            {"subject": "Weekly team meeting reminder",
             "body": "Reminder: weekly sync at 2 PM.", "service": ["Company"]},
            {"subject": "Monthly newsletter - {month}",
             "body": "This month's updates and company news.", "service": ["Newsletter"]},
            {"subject": "Invoice #{invoice_num} for your recent purchase",
             "body": "Thank you for your purchase. See invoice.", "service": ["Company"]},
            {"subject": "Your order has shipped",
             "body": "Order #{order_num} shipped.", "service": ["Amazon", "Store"]},
            {"subject": "Receipt for your subscription",
             "body": "Subscription payment of ${amount} processed.", "service": ["Service"]},
            {"subject": "Meeting notes from {date}",
             "body": "Here are notes from today's meeting.", "service": ["Company"]},
            {"subject": "Project update - Q4 progress",
             "body": "Project on track, 75% milestones done.", "service": ["Company"]} 
        ]
        locations = ["New York", "London", "Tokyo", "Moscow", "Unknown Location"]  # location samples
        months = ["January", "February", "March", "April", "May"]  # month samples

        data = []  # container to accumulate generated samples
        for i in range(n_samples):  # loop to create n_samples rows
            is_phish = random.random() < 0.5  # randomly choose class with equal probability ~50%
            if is_phish:
                template = random.choice(phishing_templates)  # pick a phishing template
                service = random.choice(template["service"])  # pick a service provider for placeholders
                location = random.choice(locations)  # pick location placeholder
                # fill subject placeholder values
                subject = template["subject"].format(service=service, location=location)
                # craft a fake verification url unique per sample
                body = template["body"].format(
                    service=service,
                    location=location,
                    url=f"http://{service.lower()}-verify-{random.randint(1000,9999)}.com/login"
                )
            else:
                template = random.choice(legitimate_templates)  # pick a legitimate email template
                service = random.choice(template["service"])  # pick service for placeholders
                month = random.choice(months)  # pick a random month
                # format subject with placeholders like month, invoice/order numbers, fixed date
                subject = template["subject"].format(
                    service=service,
                    month=month,
                    invoice_num=random.randint(10000, 99999),
                    order_num=random.randint(100000, 999999),
                    date="Oct 25, 2025"
                )
                # format body with generated amounts and numbers
                body = template["body"].format(
                    service=service,
                    amount=random.randint(10, 100),
                    invoice_num=random.randint(10000, 99999),
                    order_num=random.randint(100000, 999999)
                )
            label = 1 if is_phish else 0  # label 1 for phishing, 0 for legitimate
            # compute semantic feature values from combined subject+body
            semantic_features = self._generate_semantic_features(subject + " " + body, is_phish)
            # compute behavioral feature values based on whether phishing or not
            behavioral_features = self._generate_behavioral_features(is_phish)
            # append a dictionary representing the sample (columns of DataFrame)
            data.append({
                "email_id": i,
                "subject": subject,
                "body": body,
                "full_text": subject + " " + body,
                "label": label,
                **semantic_features,
                **behavioral_features
            })
        return pd.DataFrame(data)  # return the constructed DataFrame

    def _generate_semantic_features(self, text, is_phish):
        # count urls by regex; counts http or https occurrences
        url_count = len(re.findall(r'http[s]?://\S+', text))
        # list of urgency-related words used to compute urgency_score
        urgency_words = [
            'urgent', 'immediate', 'asap', 'now', 'quickly', 'expire', 'suspended',
            'verify', 'confirm', 'act now', 'limited time', 'final notice', 'action required'
        ]
        # urgency_score: fraction of urgency words that appear in the text
        urgency_score = sum(1 for w in urgency_words if w.lower() in text.lower()) / len(urgency_words)
        # synthetic misspelling score higher for phishing (simulates typos)
        misspelling_score = random.uniform(0.08, 0.4) if is_phish else random.uniform(0., 0.08)
        # return dictionary of computed semantic features
        return {
            "url_count": url_count,
            "urgency_score": urgency_score,
            "text_length": len(text),
            "word_count": len(text.split()),
            "misspelling_score": misspelling_score,
            "exclamation_count": text.count('!'),
            "capital_ratio": sum(1 for c in text if c.isupper()) / len(text) if len(text) > 0 else 0
        }

    def _generate_behavioral_features(self, is_phish):
        # behavioral features simulate user interaction signals; different ranges for phishing vs legit
        if is_phish:
            return {
                'mouse_entropy': random.uniform(0.7, 1.0),  # higher entropy simulated for suspicious sessions
                'click_hesitation': random.uniform(5, 15),  # longer hesitation for suspicious links
                'scroll_anomaly': random.uniform(0.6, 1.0),
                'hover_duration': random.uniform(2, 8),
                'typing_variance': random.uniform(0.5, 1.0),
                'session_time': random.uniform(30, 300),  # longer sessions in suspicious cases
                'return_visits': random.randint(0, 3),
                'forward_attempts': random.randint(0, 5)
            }
        else:
            return {
                'mouse_entropy': random.uniform(0.1, 0.4),  # calmer mouse movement for legit users
                'click_hesitation': random.uniform(0.5, 2),
                'scroll_anomaly': random.uniform(0.0, 0.3),
                'hover_duration': random.uniform(0.2, 1.5),
                'typing_variance': random.uniform(0.0, 0.2),
                'session_time': random.uniform(5, 50),
                'return_visits': random.randint(0, 1),
                'forward_attempts': random.randint(0, 1)
            }

# ===============================================================
# ========== Multimodal neural network (text + behavioral features) ==========
# ===============================================================
class MultiModalFusionAttention(nn.Module):
    def __init__(self, semantic_dim=384, behavioral_dim=8, hidden_dim=128):
        super().__init__()  # initialize parent nn.Module
        # encoder to reduce semantic embedding into hidden_dim representation
        self.semantic_encoder = nn.Sequential(
            nn.Linear(semantic_dim, hidden_dim),  # linear projection from semantic_dim to hidden_dim
            nn.ReLU(),  # non-linearity
            nn.BatchNorm1d(hidden_dim),  # batch normalization for stable training
            nn.Dropout(0.2),  # dropout for regularization
            nn.Linear(hidden_dim, hidden_dim)  # another linear layer keeping same dimension
        )
        # encoder for behavioral numeric features; maps behavioral_dim -> hidden_dim
        self.behavioral_encoder = nn.Sequential(
            nn.Linear(behavioral_dim, hidden_dim // 2),  # reduce to half hidden dim first
            nn.ReLU(),
            nn.BatchNorm1d(hidden_dim // 2),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim // 2, hidden_dim)  # map to full hidden_dim
        )
        # multi-head attention to allow cross-modal attention between semantic & behavioral encodings
        self.attention = nn.MultiheadAttention(hidden_dim, num_heads=4, batch_first=True)
        # fusion layer that combines both attention outputs into single logit
        self.fusion_layer = nn.Sequential(
            nn.Linear(hidden_dim * 2, 64),  # concatenate two hidden vectors then reduce
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.Dropout(0.1),
            nn.Linear(64, 1)  # final logit output (before sigmoid)
        )

    def forward(self, semantic_features, behavioral_features):
        semantic_encoded = self.semantic_encoder(semantic_features)  # encode semantic embeddings
        behavioral_encoded = self.behavioral_encoder(behavioral_features)  # encode behavioral features
        # apply attention where semantic queries attend to behavioral keys/values
        semantic_attn, _ = self.attention(
            semantic_encoded.unsqueeze(1), behavioral_encoded.unsqueeze(1), behavioral_encoded.unsqueeze(1)
        )
        # apply attention where behavioral queries attend to semantic keys/values
        behavioral_attn, _ = self.attention(
            behavioral_encoded.unsqueeze(1), semantic_encoded.unsqueeze(1), semantic_encoded.unsqueeze(1)
        )
        semantic_attn = semantic_attn.squeeze(1)  # remove sequence dimension (batch, 1, hidden) -> (batch, hidden)
        behavioral_attn = behavioral_attn.squeeze(1)  # same for behavioral attention
        fused = torch.cat([semantic_attn, behavioral_attn], dim=1)  # concatenate along feature axis
        output = torch.sigmoid(self.fusion_layer(fused))  # apply fusion and sigmoid to get probability-like output
        return output  # returns tensor of shape (batch_size, 1) with values in (0,1)

# ===============================================================
# ========== Feature extraction from text and behavioral features ==========
# ===============================================================
class AdvancedFeatureExtractor:
    def __init__(self):
        # load a lightweight sentence-transformers model for semantic embeddings
        self.sentence_model = SentenceTransformer('all-MiniLM-L6-v2')

    def semantic(self, texts):
        if isinstance(texts, str):
            texts = [texts]  # ensure list input for batch encoding
        # encode text(s) to dense vectors; convert_to_tensor=False returns numpy arrays
        embeddings = self.sentence_model.encode(texts, convert_to_tensor=False)
        return torch.FloatTensor(embeddings)  # convert to PyTorch FloatTensor

    def behavioral(self, df):
        # specify behavioral columns order for model input
        cols = [
            'mouse_entropy', 'click_hesitation', 'scroll_anomaly',
            'hover_duration', 'typing_variance', 'session_time',
            'return_visits', 'forward_attempts'
        ]
        return torch.FloatTensor(df[cols].values)  # return behavioral data as FloatTensor

# ===============================================================
# ========== Generate data, extract features, train the model ==========
# ===============================================================
print("Generating dataset...")  # debug print to indicate dataset generation start
dataset_gen = EnhancedPhishingDataset()  # instantiate dataset generator class
df = dataset_gen.generate_dataset(2000)  # generate 2000 synthetic email samples

print(df['label'].value_counts())  # print class distribution counts to console
assert df['label'].nunique() == 2, "Labels not binary!"  # ensure binary labels exist

print("Extracting features...")  # notify that feature extraction begins
feature_extractor = AdvancedFeatureExtractor()  # instantiate feature extractor
X_semantic = feature_extractor.semantic(df['full_text'].tolist())  # compute semantic embeddings for all emails
X_behavioral = feature_extractor.behavioral(df)  # get behavioral features from DataFrame
y = torch.FloatTensor(df['label'].values).unsqueeze(1)  # create labels tensor with shape (n,1)

# Split data into train/test; note we split both semantic and behavioral tensors accordingly
X_train_s, X_test_s, X_train_b, X_test_b, y_train, y_test = train_test_split(
    X_semantic, X_behavioral, y, test_size=0.2, random_state=SEED, stratify=y
)

print("Training model...")  # notify training start
model = MultiModalFusionAttention(
    semantic_dim=X_semantic.shape[1],  # set semantic_dim from embedding shape
    behavioral_dim=X_behavioral.shape[1]  # set behavioral_dim from feature vector length
)

criterion = nn.BCELoss()  # binary cross-entropy loss for single-output sigmoid predictions
optimizer = optim.Adam(model.parameters(), lr=0.0007, weight_decay=1e-5)  # Adam optimizer with small LR & weight decay

best_f1 = 0  # tracking best validation F1 score
for epoch in range(15):  # training loop for 15 epochs
    model.train()  # set model to training mode (affects dropout & batchnorm)
    optimizer.zero_grad()  # clear gradients before backprop
    outputs = model(X_train_s, X_train_b)  # forward pass on training tensors
    loss = criterion(outputs, y_train)  # compute loss between outputs and ground truth
    loss.backward()  # backpropagate gradients
    optimizer.step()  # update model parameters

    model.eval()  # switch to evaluation mode for validation
    with torch.no_grad():  # disable gradient calculation for efficiency
        val_outputs = model(X_test_s, X_test_b)  # forward pass on validation set
        val_loss = criterion(val_outputs, y_test)  # compute validation loss
        val_probs = val_outputs.squeeze().numpy()  # convert to numpy array of probabilities
        val_pred = (val_probs > 0.5).astype(np.int32)  # threshold probabilities at 0.5 for class predictions
        val_true = y_test.squeeze().numpy().astype(np.int32)  # true labels as numpy ints
        val_acc = accuracy_score(val_true, val_pred)  # compute accuracy
        val_f1 = f1_score(val_true, val_pred)  # compute F1 score
        cm = confusion_matrix(val_true, val_pred)  # compute confusion matrix
        print(f"Epoch {epoch+1}: Val Loss={val_loss.item():.4f}, Val Acc={val_acc:.4f}, Val F1={val_f1:.4f}")
        print("Val Confusion Matrix:\n", cm)  # show confusion matrix for diagnostic
        if val_f1 > best_f1:  # update best_f1 if improved
            best_f1 = val_f1

print("Model training complete!")  # print training finished message
print(f"Final validation F1: {best_f1:.4f}")  # print best validation F1 achieved

# ===============================================================
# ========== Robust API endpoint for prediction ==========
# ===============================================================
@app.route('/api/predict', methods=['POST'])
def predict():
    """
    POST endpoint /api/predict expects JSON: {'text': ...}.
    Returns classification: safe, suspicious, or fraudulent.
    """
    data = request.get_json()  # parse JSON payload from POST request
    text = data.get('text', '')  # get 'text' from payload; default to empty string if not present
    if not text:  # return error if no text provided
        return jsonify({'error': 'No text provided'}), 400

    try:
        # Extract semantic feature
        semantic = feature_extractor.semantic([text])  # compute embedding for the input text

        # Suspicious keyword list (improved variants)
        suspicious_keywords = [
            'urgent', 'immediate', 'asap', 'now', 'quickly', 'expire', 'suspend', 'suspended',
            'verify', 'confirm', 'act now', 'limited time', 'final notice', 'action required',
            'click here', 'security alert', 'update', 'login', 'password', 'reset', 'account locked'
        ]

        # count how many suspicious keywords appear in the input text (word-boundary aware)
        keyword_count = sum(
            re.search(rf"\b{kw}\b", text.lower()) is not None for kw in suspicious_keywords
        )

        # list of which suspicious keywords triggered (useful for debugging/inspection)
        triggered_keywords = [
            kw for kw in suspicious_keywords if re.search(rf"\b{kw}\b", text.lower())
        ]

        # Behavioral profile assignment (based on keyword strength)
        # If many suspicious keywords exist, simulate a high-risk behavioral vector
        if keyword_count >= 2:
            behavioral = torch.FloatTensor([[0.9, 13, 0.85, 5, 0.8, 180, 3, 4]])
        elif keyword_count == 1:
            behavioral = torch.FloatTensor([[0.6, 8, 0.5, 2.5, 0.4, 90, 1, 1]])
        else:
            behavioral = torch.FloatTensor([[0.2, 1, 0.1, 0.3, 0.05, 20, 0, 0]])

        model.eval()  # set model to evaluation mode before inference
        with torch.no_grad():  # disable gradients for inference
            output = model(semantic, behavioral)  # model prediction (probability-like)
            prob_val = float(output.squeeze().item())  # get scalar float probability

        # debug print to server console showing computed probability and detected keywords
        print(f"DEBUG → prob_val: {prob_val:.4f}, keyword_count: {keyword_count}, triggers: {triggered_keywords}")

        # Revised classification thresholds (decision policy combining keywords and model probability)
        if keyword_count >= 2 or prob_val >= 0.55:
            label = "fraudulent"  # high risk
        elif keyword_count == 1 or (0.35 <= prob_val < 0.55):
            label = "suspicious"  # medium risk
        else:
            label = "safe"  # low risk

        # return JSON response containing classification, probability and metadata
        return jsonify({
            'classification': label,
            'prediction_prob': round(prob_val, 4),
            'trigger_keywords': triggered_keywords,
            'raw_keyword_count': keyword_count,
            'status': 'success'
        })

    except Exception as e:
        # catch runtime errors and respond with 500 and error message
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'message': 'PhishBuster API is running'})  # simple healthcheck endpoint

if __name__ == '__main__':
    print("\n" + "="*50)  # aesthetic separator when starting server
    print("PhishBuster API Server Starting...")  # startup message
    print("="*50 + "\n")  # closing separator
    app.run(debug=True, port=5000)  # launch Flask dev server on port 5000 with debug mode enabled
