"""
Unit tests for JWT Detector
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock


class TestJWTDetector:
    """Test JWT vulnerability detection"""
    
    @pytest.mark.detector
    def test_detect_jwt_in_text(self):
        """Test detection of JWT token in text"""
        from detectors.jwt_detector import detect_jwt_from_text
        
        text = """
        Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
        """
        findings = detect_jwt_from_text(text, {})
        
        assert len(findings) > 0
        assert any('JWT' in f.get('type', '') for f in findings)
    
    @pytest.mark.detector
    def test_decode_jwt_header(self):
        """Test JWT header decoding"""
        from detectors.jwt_detector import decode_jwt_part
        
        # Standard JWT header (HS256)
        header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        decoded = decode_jwt_part(header)
        
        assert decoded is not None
        assert 'alg' in decoded
        assert decoded['alg'] == 'HS256'
    
    @pytest.mark.detector
    def test_detect_algorithm_none(self):
        """Test detection of 'none' algorithm vulnerability"""
        from detectors.jwt_detector import detect_jwt_from_text
        
        # JWT with "none" algorithm
        text = 'Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0.'
        findings = detect_jwt_from_text(text, {})
        
        # Should detect algorithm:none vulnerability
        assert len(findings) > 0
    
    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_jwt_detector_runs(self):
        """Test that JWT detector runs without crashing"""
        from detectors.jwt_detector import detect
        
        url = "https://example.com/api/profile"
        config = {'timeout': 5}
        
        # Mock HTTP requests
        with patch('aiohttp.ClientSession') as MockSession:
            mock_session = MagicMock()
            mock_get = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='{"user": "test"}')
            mock_response.headers = {'Authorization': 'Bearer token123'}
            mock_get.__aenter__.return_value = mock_response
            mock_session.get.return_value = mock_get
            MockSession.return_value.__aenter__.return_value = mock_session
            
            findings = await detect(url, config)
            
            # Should return a list
            assert isinstance(findings, list)
    
    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_jwt_handles_timeout(self):
        """Test timeout handling"""
        from detectors.jwt_detector import detect
        
        url = "https://slow.com/api"
        config = {'timeout': 1}
        
        with patch('aiohttp.ClientSession') as MockSession:
            mock_session = MagicMock()
            mock_session.get.side_effect = asyncio.TimeoutError("Timeout")
            MockSession.return_value.__aenter__.return_value = mock_session
            
            findings = await detect(url, config)
            
            # Should handle timeout gracefully
            assert isinstance(findings, list)
    
    @pytest.mark.detector
    def test_weak_secret_detection(self):
        """Test detection of weak JWT secrets"""
        from detectors.jwt_detector import WEAK_SECRETS
        
        # Verify we have a good list of weak secrets
        assert len(WEAK_SECRETS) > 10
        assert 'secret' in WEAK_SECRETS
        assert 'password' in WEAK_SECRETS
        assert '123456' in WEAK_SECRETS
