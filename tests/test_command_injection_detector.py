"""
Unit tests for Command Injection Detector
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
import time


class TestCommandInjectionDetector:
    """Test Command Injection detection"""
    
    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_command_injection_detector_runs(self):
        """Test that Command Injection detector runs without crashing"""
        from detectors.command_injection_detector import command_injection_detector as detect
        
        url = "https://example.com/ping?host=localhost"
        config = {'timeout': 5}
        
        # Mock HTTP requests
        with patch('aiohttp.ClientSession') as MockSession:
            mock_session = MagicMock()
            mock_get = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value="PING localhost (127.0.0.1)")
            mock_get.__aenter__.return_value = mock_response
            mock_session.get.return_value = mock_get
            MockSession.return_value.__aenter__.return_value = mock_session
            
            findings = await detect(url, config)
            
            # Should return a list
            assert isinstance(findings, list)
    
    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_command_injection_handles_timeout(self):
        """Test timeout handling"""
        from detectors.command_injection_detector import command_injection_detector as detect
        
        url = "https://slow.com/cmd"
        config = {'timeout': 1}
        
        with patch('aiohttp.ClientSession') as MockSession:
            mock_session = MagicMock()
            mock_session.get.side_effect = asyncio.TimeoutError("Timeout")
            MockSession.return_value.__aenter__.return_value = mock_session
            
            findings = await detect(url, config)
            
            # Should handle timeout gracefully
            assert isinstance(findings, list)
    
    @pytest.mark.detector
    @pytest.mark.asyncio
    async def test_command_injection_handles_errors(self):
        """Test error handling"""
        from detectors.command_injection_detector import command_injection_detector as detect
        
        url = "https://error.com/cmd"
        config = {'timeout': 5}
        
        with patch('aiohttp.ClientSession') as MockSession:
            mock_session = MagicMock()
            mock_session.get.side_effect = Exception("Network error")
            MockSession.return_value.__aenter__.return_value = mock_session
            
            findings = await detect(url, config)
            
            # Should handle errors gracefully
            assert isinstance(findings, list)
