from functools import lru_cache
import os
import pickle
import re
import socket
from urllib.parse import urlparse

import torch
import torch.nn as nn

from app.utils import normalize_url
from app.schemas import PhishingResponse
from app.config import settings

embedding_dim: int = 128
hidden_size: int = 128
num_layers: int = 2
max_len_url = 200


class GRUClassifierWithEmbedding(nn.Module):
    def __init__(self, vocab_size, embedding_dim, hidden_size, num_layers):
        super(GRUClassifierWithEmbedding, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.gru = nn.GRU(embedding_dim, hidden_size, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_size, 1)

    def forward(self, x):
        embedded = self.embedding(x) 
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size)
        out, _ = self.gru(embedded, h0)
        out = self.fc(out[:, -1, :])  
        return torch.sigmoid(out)
    

class PhishingDetector():
    def __init__(self, blacklist_domain, 
                 blacklist_ip, 
                 blacklist_url,
                 download_dir, 
                 model_file, 
                 vocab_file):
        
        self.blacklist_url = os.path.join(download_dir, blacklist_url)
        self.blacklist_domain = os.path.join(download_dir, blacklist_domain)
        self.blacklist_ip = os.path.join(download_dir, blacklist_ip)
        self.model_file = os.path.join(download_dir, model_file)
        self.vocab_file = os.path.join(download_dir, vocab_file)
        self.update_blacklist()
        self.load_model()
        
    def load_model(self):
        with open(self.vocab_file, 'rb') as f:
            self.vocab = pickle.load(f)
        
        vocab_size = len(self.vocab) + 1
        self.rnn_model = GRUClassifierWithEmbedding(vocab_size, embedding_dim, hidden_size, num_layers)
        self.rnn_model.load_state_dict(torch.load(self.model_file, map_location=torch.device('cpu')))
        self.rnn_model.eval() 

    def update_blacklist(self):
        with open(self.blacklist_url) as f:
            self.urls = set(map(lambda x: x.strip(), f.readline()))
        with open(self.blacklist_domain) as f:
            self.domains = set(map(lambda x: x.strip(), f.readline()))
        with open(self.blacklist_ip) as f:
            self.ips = set(map(lambda x: x.strip(), f.readline()))

    def check_ip(self, url):
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return False
            if re.fullmatch(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
                return hostname in self.ips
            try:
                ip_list = {
                    info[4][0]
                    for info in socket.getaddrinfo(
                        hostname, None, family=socket.AF_INET, type=socket.SOCK_STREAM
                    )
                }
            except (socket.gaierror, socket.timeout):
                return False
            return any(ip in self.ips for ip in ip_list)
        except Exception:
            return False

    def check_domain(self, url):
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return False
            return hostname in self.domains
        except Exception:
            return False
    
    def check_url_simple(self, url):
        url = normalize_url(url)
        return url in self.urls
    
    def check_url_rnn(self, url):
        indexed = [self.vocab.get(c, 0) for c in url[:max_len_url]]
        indexed += [0] * (max_len_url - len(indexed))
        input_tensor = torch.LongTensor(indexed).unsqueeze(0)
        with torch.no_grad():
            probability = self.rnn_model(input_tensor).item()
            return probability
        
    
    def check_url(self, url):
        if self.check_url_simple(url):
            return PhishingResponse(is_phishing = True, confidence_level = 1.0, reason = "URL in blacklist!")
        if self.check_domain(url):
            return PhishingResponse(is_phishing = True, confidence_level = 1.0, reason = "Domain in blacklist!")
        if self.check_ip(url):
            return PhishingResponse(is_phishing = True, confidence_level = 1.0, reason = "IP in blacklist!")
        prob = self.check_url_rnn(url)
        if prob > 0.8:
            return PhishingResponse(is_phishing = True, confidence_level = prob, reason = "Checking in RNN.")
        else:
            return PhishingResponse(is_phishing = False, confidence_level = prob, reason = "All checks are ok!")

@lru_cache(maxsize=1)
def get_phishing_detector():
    return PhishingDetector(blacklist_domain=settings.BLACKLIST_DOMAINS_FILE,
                            blacklist_ip=settings.BLACKLIST_IPS_FILE,
                            blacklist_url=settings.BLACKLIST_URLS_FILE,
                            download_dir=settings.DOWNLOAD_DIR,
                            model_file='best_model.pth',
                            vocab_file='vocab.pkl')

