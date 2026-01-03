"""
API Documentation Discovery for 0-Day Hunting
Discovers exposed API documentation that reveals hidden endpoints
"""
import requests
from urllib.parse import urljoin
from typing import Dict, List, Any
import json


class APIDocsDiscovery:
    """
    Discovers exposed API documentation:
    - Swagger/OpenAPI specs
    - GraphQL introspection
    - API documentation pages
    - Postman collections
    - WADL files
    """
    
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.findings = []
        self.discovered_endpoints = []
        
        # Common API documentation paths
        self.doc_paths = [
            # Swagger/OpenAPI
            '/swagger',
            '/swagger-ui',
            '/swagger-ui.html',
            '/swagger/index.html',
            '/api/swagger',
            '/api/swagger-ui',
            '/api/swagger.json',
            '/api/swagger.yaml',
            '/swagger.json',
            '/swagger.yaml',
            '/openapi.json',
            '/openapi.yaml',
            '/api/openapi.json',
            '/v1/swagger.json',
            '/v2/swagger.json',
            '/api-docs',
            '/api/docs',
            '/docs',
            '/documentation',
            
            # GraphQL
            '/graphql',
            '/graphiql',
            '/api/graphql',
            '/graphql/console',
            
            # RAML/WADL
            '/api.raml',
            '/application.wadl',
            '/api/application.wadl',
            
            # Postman
            '/postman',
            '/postman_collection.json',
            '/api/postman',
            
            # API Blueprint
            '/api.md',
            '/api-blueprint',
            
            # Other common paths
            '/redoc',
            '/rapidoc',
            '/api',
            '/api/v1',
            '/api/v2',
            '/rest',
            '/api/rest',
        ]
    
    def run(self) -> Dict[str, Any]:
        """Main execution method"""
        try:
            # Check each documentation path
            for path in self.doc_paths:
                url = urljoin(self.target, path)
                doc_info = self.check_api_docs(url)
                
                if doc_info:
                    self.findings.append(doc_info)
                    
                    # Try to extract endpoints if it's a spec file
                    if doc_info['type'] in ['swagger', 'openapi']:
                        self.extract_swagger_endpoints(url)
                    elif doc_info['type'] == 'graphql':
                        self.extract_graphql_schema(url)
            
            return {
                'vulnerable': len(self.findings) > 0,
                'severity': self.calculate_severity(),
                'findings': self.findings,
                'documentation_count': len(self.findings),
                'endpoints_discovered': len(self.discovered_endpoints),
                'details': {
                    'swagger_docs': [f for f in self.findings if f['type'] in ['swagger', 'openapi']],
                    'graphql_endpoints': [f for f in self.findings if f['type'] == 'graphql'],
                    'api_docs': [f for f in self.findings if f['type'] == 'api_docs'],
                    'discovered_endpoints': self.discovered_endpoints[:50],  # Limit to 50
                }
            }
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'findings': []
            }
    
    def check_api_docs(self, url: str) -> Dict[str, Any]:
        """Check if API documentation exists at URL"""
        try:
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            
            if response.status_code != 200:
                return None
            
            content = response.text.lower()
            content_type = response.headers.get('content-type', '').lower()
            
            # Detect Swagger/OpenAPI
            if any(keyword in content for keyword in ['swagger', 'openapi', 'swaggerui']):
                return {
                    'type': 'swagger',
                    'severity': 'high',
                    'url': url,
                    'description': 'Swagger/OpenAPI documentation exposed',
                    'details': 'May reveal all API endpoints including internal ones'
                }
            
            # Detect GraphQL
            if 'graphql' in content or 'graphiql' in content:
                return {
                    'type': 'graphql',
                    'severity': 'high',
                    'url': url,
                    'description': 'GraphQL endpoint/console exposed',
                    'details': 'Introspection may reveal entire API schema'
                }
            
            # Detect JSON/YAML API specs
            if 'application/json' in content_type or url.endswith(('.json', '.yaml', '.yml')):
                try:
                    data = json.loads(response.text)
                    if 'swagger' in data or 'openapi' in data or 'paths' in data:
                        return {
                            'type': 'openapi',
                            'severity': 'high',
                            'url': url,
                            'description': 'OpenAPI specification file exposed',
                            'details': f"Contains {len(data.get('paths', {}))} API endpoints"
                        }
                except:
                    pass
            
            # Detect API documentation pages
            if any(keyword in content for keyword in ['api documentation', 'rest api', 'api reference']):
                return {
                    'type': 'api_docs',
                    'severity': 'medium',
                    'url': url,
                    'description': 'API documentation page exposed',
                    'details': 'May contain undocumented endpoints and examples'
                }
            
            return None
        except:
            return None
    
    def extract_swagger_endpoints(self, url: str):
        """Extract endpoints from Swagger/OpenAPI spec"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            data = json.loads(response.text)
            
            paths = data.get('paths', {})
            
            for path, methods in paths.items():
                for method in methods.keys():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        endpoint = {
                            'method': method.upper(),
                            'path': path,
                            'description': methods[method].get('summary', 'No description')
                        }
                        self.discovered_endpoints.append(endpoint)
        except:
            pass
    
    def extract_graphql_schema(self, url: str):
        """Try GraphQL introspection query"""
        introspection_query = {
            "query": """
            {
                __schema {
                    types {
                        name
                        kind
                        description
                    }
                    queryType { name }
                    mutationType { name }
                }
            }
            """
        }
        
        try:
            response = requests.post(
                url,
                json=introspection_query,
                timeout=10,
                verify=False,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data['data']:
                    types = data['data']['__schema'].get('types', [])
                    
                    self.findings.append({
                        'type': 'graphql_introspection',
                        'severity': 'high',
                        'url': url,
                        'description': 'GraphQL introspection enabled',
                        'details': f"Discovered {len(types)} GraphQL types"
                    })
        except:
            pass
    
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
    discovery = APIDocsDiscovery(target)
    return discovery.run()
