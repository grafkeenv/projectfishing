import pytest
from unittest.mock import MagicMock, patch
import torch


from app.phishing_detect import (
    PhishingDetector,
    GRUClassifierWithEmbedding,
    get_phishing_detector
)
from app.schemas import PhishingResponse


@pytest.fixture
def mock_detector():
    with patch('builtins.open'), \
         patch('pickle.load'), \
         patch('torch.load'):
        detector = PhishingDetector(
            blacklist_domain="domains.txt",
            blacklist_ip="ips.txt",
            blacklist_url="urls.txt",
            download_dir="test_dir",
            model_file="model.pth",
            vocab_file="vocab.pkl"
        )
        detector.urls = {"http://malicious.com"}
        detector.domains = {"evil.com"}
        detector.ips = {"1.2.3.4"}
        detector.vocab = {"h": 1, "t": 2, "p": 3, ":": 4, "/": 5}
        detector.rnn_model = MagicMock(spec=GRUClassifierWithEmbedding)
        detector.rnn_model.return_value = torch.tensor([0.9])
        return detector

def test_check_url_simple_blacklisted(mock_detector):
    # Act
    result = mock_detector.check_url_simple("http://malicious.com")
    
    # Assert
    assert result is True

def test_check_domain_blacklisted(mock_detector):
    # Act
    result = mock_detector.check_domain("http://evil.com/path")
    
    # Assert
    assert result is True

@patch('socket.getaddrinfo')
def test_check_ip_blacklisted(mock_getaddrinfo, mock_detector):
    # Arrange
    mock_getaddrinfo.return_value = [(None, None, None, None, ("1.2.3.4",))]
    
    # Act
    result = mock_detector.check_ip("http://example.com")
    
    # Assert
    assert result is True

def test_check_url_rnn(mock_detector):
    # Arrange
    mock_detector.rnn_model.return_value.item.return_value = 0.95
    
    # Act
    result = mock_detector.check_url_rnn("http://test.com")
    
    # Assert
    assert result == 0.95

def test_check_url_blacklist_hit(mock_detector):
    # Act
    result = mock_detector.check_url("http://malicious.com")
    
    # Assert
    assert isinstance(result, PhishingResponse)
    assert result.is_phishing is True
    assert result.confidence_level == 1.0
    assert "URL in blacklist" in result.reason

def test_check_url_rnn_phishing(mock_detector):
    # Arrange
    mock_detector.rnn_model.return_value.item.return_value = 0.9
    
    # Act
    result = mock_detector.check_url("http://test.com")
    
    # Assert
    assert isinstance(result, PhishingResponse)
    assert result.is_phishing is True
    assert result.confidence_level == 0.9
    assert "Checking in RNN" in result.reason

def test_check_url_safe(mock_detector):
    # Arrange
    mock_detector.rnn_model.return_value.item.return_value = 0.1
    
    # Act
    result = mock_detector.check_url("http://safe.com")
    
    # Assert
    assert isinstance(result, PhishingResponse)
    assert result.is_phishing is False
    assert result.confidence_level == 0.1
    assert "All checks are ok" in result.reason

def test_get_phishing_detector_singleton():
    # Act
    detector1 = get_phishing_detector()
    detector2 = get_phishing_detector()
    
    # Assert
    assert detector1 is detector2