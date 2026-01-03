"""
Backup & Old File Hunter for 0-Day Discovery
Discovers exposed backup files, old systems, and sensitive file leaks
"""
import requests
from urllib.parse import urljoin
from typing import Dict, List, Any
import time


class BackupFileHunter:
    """
    Hunts for exposed backup files and old versions:
    - Database backups (.sql, .bak, .dump)
    - Source code archives (.zip, .tar.gz, .rar)
    - Configuration backups (.old, .bak, .backup)
    - Temporary files (.tmp, .swp, ~)
    """
    
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.findings = []
        
        # Common backup file patterns
        self.backup_files = [
            # Database backups
            'backup.sql',
            'database.sql',
            'db.sql',
            'dump.sql',
            'backup.bak',
            'database.bak',
            'db.dump',
            'mysql.sql',
            'postgres.sql',
            
            # Source code archives
            'backup.zip',
            'site.zip',
            'www.zip',
            'source.zip',
            'code.zip',
            'backup.tar.gz',
            'site.tar.gz',
            'backup.rar',
            
            # Configuration backups
            'config.old',
            'config.bak',
            '.env.old',
            '.env.backup',
            'settings.old',
            'web.config.old',
            
            # Old/backup directories
            'backup/',
            'backups/',
            'old/',
            '.backup/',
            '_backup/',
            
            # Common file names
            'site.bak',
            'index.old',
            'admin.old',
            'login.bak',
            
            # Git/SVN exposures
            '.git/config',
            '.svn/entries',
            '.env',
            '.DS_Store',
            
            # Temp files
            'temp.zip',
            'tmp.zip',
            '.swp',
            '~',
        ]
        
        # Common paths to prepend
        self.paths = [
            '',
            'admin/',
            'backup/',
            'backups/',
            'old/',
            'temp/',
            'files/',
            'data/',
        ]
    
    def run(self) -> Dict[str, Any]:
        """Main execution method"""
        try:
            exposed_files = []
            
            # Check each backup file pattern
            for path in self.paths:
                for backup_file in self.backup_files[:20]:  # Limit to prevent too many requests
                    url = urljoin(self.target, path + backup_file)
                    
                    if self.check_file_exists(url):
                        file_info = self.analyze_backup_file(url)
                        exposed_files.append(file_info)
                        
                        self.findings.append({
                            'type': 'exposed_backup',
                            'severity': file_info['severity'],
                            'url': url,
                            'file_type': file_info['file_type'],
                            'size': file_info.get('size', 'unknown'),
                            'description': f"Exposed {file_info['file_type']} file: {backup_file}"
                        })
                    
                    # Rate limiting
                    time.sleep(0.1)
            
            return {
                'vulnerable': len(exposed_files) > 0,
                'severity': self.calculate_severity(),
                'findings': self.findings,
                'exposed_count': len(exposed_files),
                'details': {
                    'database_backups': [f for f in self.findings if 'sql' in f['url'] or 'dump' in f['url']],
                    'source_archives': [f for f in self.findings if any(ext in f['url'] for ext in ['.zip', '.tar', '.rar'])],
                    'config_files': [f for f in self.findings if any(ext in f['url'] for ext in ['.env', 'config', 'settings'])],
                    'git_svn': [f for f in self.findings if any(d in f['url'] for d in ['.git', '.svn'])],
                }
            }
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'findings': []
            }
    
    def check_file_exists(self, url: str) -> bool:
        """Check if a file exists at the given URL"""
        try:
            response = requests.head(url, timeout=5, verify=False, allow_redirects=False)
            
            # File exists if we get 200 or 403 (forbidden but exists)
            if response.status_code in [200, 403]:
                return True
            
            # Sometimes HEAD doesn't work, try GET
            if response.status_code == 405:
                response = requests.get(url, timeout=5, verify=False, stream=True)
                return response.status_code in [200, 403]
            
            return False
        except:
            return False
    
    def analyze_backup_file(self, url: str) -> Dict[str, Any]:
        """Analyze the type and severity of backup file"""
        file_info = {
            'url': url,
            'file_type': 'unknown',
            'severity': 'medium'
        }
        
        # Determine file type and severity
        if any(ext in url for ext in ['.sql', '.dump', '.bak', 'database']):
            file_info['file_type'] = 'database_backup'
            file_info['severity'] = 'critical'
        elif any(ext in url for ext in ['.zip', '.tar.gz', '.rar']):
            file_info['file_type'] = 'source_code_archive'
            file_info['severity'] = 'high'
        elif '.env' in url or 'config' in url:
            file_info['file_type'] = 'configuration_file'
            file_info['severity'] = 'high'
        elif '.git' in url or '.svn' in url:
            file_info['file_type'] = 'version_control'
            file_info['severity'] = 'critical'
        elif any(ext in url for ext in ['.old', '.backup']):
            file_info['file_type'] = 'old_version'
            file_info['severity'] = 'medium'
        
        # Try to get file size
        try:
            response = requests.head(url, timeout=5, verify=False)
            if 'content-length' in response.headers:
                size_bytes = int(response.headers['content-length'])
                file_info['size'] = self.format_file_size(size_bytes)
        except:
            pass
        
        return file_info
    
    def format_file_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def calculate_severity(self) -> str:
        """Calculate overall severity"""
        if not self.findings:
            return 'info'
        
        severities = [f.get('severity', 'info') for f in self.findings]
        
        if 'critical' in severities:
            return 'critical'
        elif 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        return 'low'


def detect(target: str) -> Dict[str, Any]:
    """Main detection function"""
    hunter = BackupFileHunter(target)
    return hunter.run()
