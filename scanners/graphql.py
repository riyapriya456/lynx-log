"""
Lynx VAPT - GraphQL Security Scanner

Comprehensive GraphQL API security testing:
- Introspection query exploitation
- Schema extraction and analysis
- Query batching attacks
- Nested query DoS
- Authorization bypass attempts
- Injection testing in GraphQL fields
- Mutation security testing

Author: Lynx Team
"""

import asyncio
import re
import json
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from scanners.base import BaseScanner
from common import event_manager, TestingZone


@dataclass
class GraphQLEndpoint:
    """Discovered GraphQL endpoint information."""
    url: str
    introspection_enabled: bool = False
    schema: Optional[Dict] = None
    types: List[str] = field(default_factory=list)
    queries: List[str] = field(default_factory=list)
    mutations: List[str] = field(default_factory=list)
    subscriptions: List[str] = field(default_factory=list)


@dataclass
class GraphQLField:
    """GraphQL field information."""
    name: str
    type_name: str
    args: List[Dict] = field(default_factory=list)
    is_sensitive: bool = False


class GraphQLScanner(BaseScanner):
    """
    GraphQL Security Scanner.
    
    Detects and tests GraphQL endpoints for:
    - Information disclosure via introspection
    - Authorization bypass
    - Injection vulnerabilities
    - DoS via nested queries
    - Batching attacks
    - Sensitive field exposure
    """
    
    # Common GraphQL endpoint paths
    GRAPHQL_PATHS = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/api/v1/graphql",
        "/graphiql",
        "/query",
        "/api/query",
        "/gql",
        "/api/gql",
        "/__graphql",
        "/playground",
        "/console",
        "/explorer",
    ]
    
    # Introspection query
    INTROSPECTION_QUERY = '''
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }
    
    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }
    
    fragment InputValue on __InputValue {
      name
      description
      type {
        ...TypeRef
      }
      defaultValue
    }
    
    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
    '''
    
    # Simplified introspection for quick detection
    SIMPLE_INTROSPECTION = '{"query":"query{__schema{types{name}}}"}'
    
    # Sensitive field patterns
    SENSITIVE_FIELDS = [
        'password', 'passwd', 'secret', 'token', 'apikey', 'api_key',
        'credit_card', 'creditcard', 'ssn', 'social_security',
        'auth_token', 'refresh_token', 'access_token', 'private_key',
        'secret_key', 'encryption_key', 'salt', 'hash', 'otp',
        'pin', 'cvv', 'card_number', 'account_number', 'bank_account',
        'admin', 'superuser', 'root', 'internal', 'debug'
    ]
    
    # Injection payloads for GraphQL
    INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "${7*7}",
        "{{7*7}}",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "; ls -la",
    ]
    
    def __init__(self, context):
        super().__init__(context)
        self.name = "GraphQLScanner"
        self.zone = TestingZone.ZONE_D  # API Security
        self.endpoints: List[GraphQLEndpoint] = []
    
    async def run(self):
        """Run GraphQL security scan."""
        await event_manager.emit("log", f"[{self.name}] Starting GraphQL security scan...")
        
        # Discover GraphQL endpoints
        await self._discover_endpoints()
        
        if not self.endpoints:
            await event_manager.emit("log", f"[{self.name}] No GraphQL endpoints discovered")
            return
        
        await event_manager.emit("log", 
            f"[{self.name}] Found {len(self.endpoints)} GraphQL endpoint(s)")
        
        # Test each endpoint
        for endpoint in self.endpoints:
            await self._test_endpoint(endpoint)
    
    async def _discover_endpoints(self):
        """Discover GraphQL endpoints."""
        base_url = self.context.target.rstrip('/')
        
        for path in self.GRAPHQL_PATHS:
            url = urljoin(base_url, path)
            
            if await self._is_graphql_endpoint(url):
                endpoint = GraphQLEndpoint(url=url)
                self.endpoints.append(endpoint)
    
    async def _is_graphql_endpoint(self, url: str) -> bool:
        """Check if URL is a GraphQL endpoint."""
        # Try simple introspection
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        try:
            # POST request with introspection
            async with self.context.session.post(
                url,
                data=self.SIMPLE_INTROSPECTION,
                headers=headers,
                timeout=10
            ) as response:
                if response.status == 200:
                    text = await response.text()
                    try:
                        data = json.loads(text)
                        if 'data' in data and '__schema' in data.get('data', {}):
                            return True
                    except json.JSONDecodeError:
                        pass
            
            # Try GET request
            async with self.context.session.get(
                f"{url}?query={{__schema{{types{{name}}}}}}",
                headers=headers,
                timeout=10
            ) as response:
                if response.status == 200:
                    text = await response.text()
                    if '__schema' in text or 'types' in text:
                        return True
                        
        except Exception:
            pass
        
        return False
    
    async def _test_endpoint(self, endpoint: GraphQLEndpoint):
        """Run all tests on a GraphQL endpoint."""
        await self._test_introspection(endpoint)
        
        if endpoint.introspection_enabled:
            await self._analyze_schema(endpoint)
            await self._test_sensitive_fields(endpoint)
            await self._test_authorization_bypass(endpoint)
        
        await self._test_batching_attack(endpoint)
        await self._test_nested_query_dos(endpoint)
        await self._test_injection(endpoint)
    
    async def _test_introspection(self, endpoint: GraphQLEndpoint):
        """Test if introspection is enabled."""
        headers = {'Content-Type': 'application/json'}
        
        try:
            async with self.context.session.post(
                endpoint.url,
                json={'query': self.INTROSPECTION_QUERY},
                headers=headers,
                timeout=30
            ) as response:
                if response.status == 200:
                    text = await response.text()
                    data = json.loads(text)
                    
                    if 'data' in data and data['data'].get('__schema'):
                        endpoint.introspection_enabled = True
                        endpoint.schema = data['data']['__schema']
                        
                        await self.emit_vulnerability(
                            "GraphQL Introspection Enabled",
                            f"GraphQL introspection is enabled at {endpoint.url}\n"
                            f"This exposes the entire API schema to attackers.\n"
                            f"Found {len(endpoint.schema.get('types', []))} types in schema.",
                            severity="P3",
                            remediation="Disable introspection in production environments.",
                            url=endpoint.url,
                            payload="query { __schema { types { name } } }",
                            confidence=0.8,
                            observed_behavior="Schema introspection returned a valid __schema object.",
                            verification="direct",
                            reproduction_steps=[
                                "Send the introspection query to the reported endpoint.",
                                "Confirm the server returns __schema data in production.",
                                "Retest after disabling introspection to verify the behavior is gone.",
                            ],
                        )
                        
        except Exception as e:
            await event_manager.emit("log", f"[{self.name}] Introspection test error: {e}")
    
    async def _analyze_schema(self, endpoint: GraphQLEndpoint):
        """Analyze the GraphQL schema for security issues."""
        if not endpoint.schema:
            return
        
        schema = endpoint.schema
        
        # Extract types
        types = schema.get('types', [])
        
        # Find Query type
        query_type_name = schema.get('queryType', {}).get('name', 'Query')
        mutation_type_name = schema.get('mutationType', {}).get('name', 'Mutation')
        
        for type_info in types:
            type_name = type_info.get('name', '')
            
            # Skip internal types
            if type_name.startswith('__'):
                continue
            
            endpoint.types.append(type_name)
            
            # Extract fields
            fields = type_info.get('fields', []) or []
            
            for field in fields:
                field_name = field.get('name', '')
                
                if type_name == query_type_name:
                    endpoint.queries.append(field_name)
                elif type_name == mutation_type_name:
                    endpoint.mutations.append(field_name)
        
        # Log findings
        await event_manager.emit("log", 
            f"[{self.name}] Schema: {len(endpoint.types)} types, "
            f"{len(endpoint.queries)} queries, {len(endpoint.mutations)} mutations")
    
    async def _test_sensitive_fields(self, endpoint: GraphQLEndpoint):
        """Test for sensitive fields exposed in schema."""
        if not endpoint.schema:
            return
        
        sensitive_found = []
        
        for type_info in endpoint.schema.get('types', []):
            type_name = type_info.get('name', '')
            
            if type_name.startswith('__'):
                continue
            
            fields = type_info.get('fields', []) or []
            
            for field in fields:
                field_name = field.get('name', '').lower()
                
                for sensitive in self.SENSITIVE_FIELDS:
                    if sensitive in field_name:
                        sensitive_found.append(f"{type_name}.{field.get('name')}")
                        break
        
        if sensitive_found:
            await self.emit_vulnerability(
                "GraphQL Sensitive Fields Exposed",
                f"Sensitive fields found in GraphQL schema:\n" +
                "\n".join(f"  - {f}" for f in sensitive_found[:20]) +
                (f"\n  ... and {len(sensitive_found) - 20} more" if len(sensitive_found) > 20 else ""),
                severity="P2",
                remediation="Remove sensitive fields from schema or implement proper authorization.",
                url=endpoint.url,
                payload=json.dumps(sensitive_found[:5]),
                confidence=0.78,
                observed_behavior="Schema exposed fields that look sensitive by name; access control still needs validation.",
                verification="heuristic",
                reproduction_steps=[
                    "Inspect the GraphQL schema for the reported field names.",
                    "Confirm the fields are actually reachable and not server-protected.",
                    "Retest after restricting the schema or authorization paths.",
                ],
            )
    
    async def _test_authorization_bypass(self, endpoint: GraphQLEndpoint):
        """Test for authorization bypass in queries/mutations."""
        admin_operations = []
        
        # Look for admin/user operations
        admin_keywords = ['admin', 'delete', 'update', 'create', 'edit', 'modify', 'remove']
        
        for query in endpoint.queries + endpoint.mutations:
            if any(kw in query.lower() for kw in admin_keywords):
                admin_operations.append(query)
        
        if not admin_operations:
            return
        
        # Try to execute without auth
        headers = {'Content-Type': 'application/json'}
        
        for operation in admin_operations[:5]:  # Test first 5
            # Construct minimal query
            if operation in endpoint.mutations:
                query = f'mutation {{ {operation}(input: {{}}) {{ id }} }}'
            else:
                query = f'query {{ {operation} {{ id }} }}'
            
            try:
                async with self.context.session.post(
                    endpoint.url,
                    json={'query': query},
                    headers=headers,
                    timeout=10
                ) as response:
                    text = await response.text()
                    data = json.loads(text)
                    
                    # Check if operation succeeded (no auth error)
                    if 'data' in data and data['data'].get(operation):
                        await self.emit_vulnerability(
                            "GraphQL Authorization Bypass",
                            f"Admin operation '{operation}' accessible without authentication.\n"
                            f"Query: {query}",
                            severity="P1",
                            remediation="Implement proper authorization checks on all sensitive operations.",
                            url=endpoint.url,
                            payload=query,
                            confidence=0.94,
                            observed_behavior="Sensitive operation returned data without an auth error.",
                            verification="direct",
                            reproduction_steps=[
                                "Replay the reported query without authentication.",
                                "Confirm the response includes data rather than an authorization error.",
                                "Retest after enforcing authorization on the operation.",
                            ],
                        )
                        break
                        
            except Exception:
                continue
    
    async def _test_batching_attack(self, endpoint: GraphQLEndpoint):
        """Test for query batching vulnerabilities."""
        headers = {'Content-Type': 'application/json'}
        
        # Batched login attempts
        batch_query = [
            {'query': 'query { __typename }'},
            {'query': 'query { __typename }'},
            {'query': 'query { __typename }'},
        ] * 10  # 30 queries
        
        try:
            async with self.context.session.post(
                endpoint.url,
                json=batch_query,
                headers=headers,
                timeout=10
            ) as response:
                if response.status == 200:
                    text = await response.text()
                    data = json.loads(text)
                    
                    if isinstance(data, list) and len(data) == 30:
                        await self.emit_vulnerability(
                            "GraphQL Batching Attack Possible",
                            f"GraphQL endpoint accepts batched queries.\n"
                            f"Sent 30 queries in single request, all were processed.\n"
                            f"This can be used to bypass rate limiting (e.g., brute force login).",
                            severity="P3",
                            remediation="Implement query batch limits and rate limiting per query.",
                            url=endpoint.url,
                            payload="[{query:...}, {query:...}, ...] x30",
                            confidence=0.6,
                            observed_behavior="The server processed a large batch, but rate-limit bypass was not directly proven.",
                            verification="heuristic",
                        )
                        
        except Exception:
            pass
    
    async def _test_nested_query_dos(self, endpoint: GraphQLEndpoint):
        """Test for nested query denial of service."""
        # Create a deeply nested query (if we know the schema)
        # This is a simplified test
        
        headers = {'Content-Type': 'application/json'}
        
        # Look for self-referential types
        if not endpoint.schema:
            return
        
        # Find types that reference themselves (e.g., User -> friends: [User])
        self_ref_types = []
        
        for type_info in endpoint.schema.get('types', []):
            type_name = type_info.get('name', '')
            fields = type_info.get('fields', []) or []
            
            for field in fields:
                field_type = self._get_type_name(field.get('type', {}))
                if field_type == type_name:
                    self_ref_types.append((type_name, field.get('name')))
        
        if self_ref_types:
            type_name, field_name = self_ref_types[0]
            
            # Create deeply nested query
            depth = 10
            nested = f"{field_name} {{ id }}"
            for _ in range(depth):
                nested = f"{field_name} {{ {nested} }}"
            
            query = f"query {{ {endpoint.queries[0] if endpoint.queries else '__typename'} {{ {nested} }} }}"
            
            await self.emit_vulnerability(
                "GraphQL Nested Query DoS Possible",
                f"Schema contains self-referential type '{type_name}' via field '{field_name}'.\n"
                f"This can be exploited for denial of service with deeply nested queries.\n"
                f"Example: {query[:200]}...",
                severity="P3",
                remediation="Implement query depth limiting and complexity analysis.",
                url=endpoint.url,
                payload=query[:100],
                confidence=0.58,
                observed_behavior="Schema structure permits recursive nesting, but DoS was not executed here.",
                verification="heuristic",
            )
    
    def _get_type_name(self, type_ref: Dict) -> str:
        """Extract type name from GraphQL type reference."""
        if not type_ref:
            return ""
        
        name = type_ref.get('name')
        if name:
            return name
        
        of_type = type_ref.get('ofType')
        if of_type:
            return self._get_type_name(of_type)
        
        return ""
    
    async def _test_injection(self, endpoint: GraphQLEndpoint):
        """Test for injection vulnerabilities in GraphQL."""
        headers = {'Content-Type': 'application/json'}
        
        # Get a simple query field to test
        test_field = None
        if endpoint.queries:
            test_field = endpoint.queries[0]
        
        if not test_field:
            test_field = "__typename"
        
        for payload in self.INJECTION_PAYLOADS:
            # Test in query arguments
            query = f'query {{ {test_field}(id: "{payload}") {{ id }} }}'
            
            try:
                async with self.context.session.post(
                    endpoint.url,
                    json={'query': query},
                    headers=headers,
                    timeout=10
                ) as response:
                    text = await response.text()
                    
                    # Check for injection indicators
                    if any(indicator in text.lower() for indicator in [
                        'sql', 'syntax error', 'mysql', 'postgresql',
                        'uid=', 'root:', 'etc/passwd', 
                        '<script>', 'alert(1)', '49'
                    ]):
                        await self.emit_vulnerability(
                            "GraphQL Injection Vulnerability",
                            f"Potential injection vulnerability in GraphQL field.\n"
                            f"Payload: {payload}\n"
                            f"Response indicates injection success.",
                            severity="P1",
                            remediation="Implement proper input validation and parameterized queries.",
                            url=endpoint.url,
                            payload=payload,
                            confidence=0.74,
                            observed_behavior="Injected payload triggered an error-like response pattern.",
                            verification="heuristic",
                            reproduction_steps=[
                                "Send the reported payload against the field in a clean session.",
                                "Compare the response against a baseline request.",
                                "Only confirm exploitation if a second request reproduces the same injection marker.",
                            ],
                        )
                        return
                        
            except Exception:
                continue
    
    def cleanup(self):
        """Cleanup scanner resources."""
        self.endpoints.clear()
