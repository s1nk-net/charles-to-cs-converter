#!/usr/bin/env python3
"""
Charles Proxy to Cobalt Strike Profile Converter
Converts captured HTTP traffic into malleable C2 profile blocks
"""

import json
import re
import sys
import argparse
from urllib.parse import urlparse, parse_qs
from pathlib import Path
import base64
import random

class CharlesToCSConverter:
    def __init__(self):
        self.common_params = [
            'q', 'search', 'query', 'id', 'sid', 'sessionid', 'token', 'auth',
            'key', 'api_key', 'callback', 'format', 'type', 'action', 'cmd',
            'data', 'payload', 'content', 'message', 'response', 'result'
        ]
        
        self.cs_encodings = [
            'base64', 'base64url', 'netbios', 'netbiosu', 'mask'
        ]
    
    def parse_har_file(self, har_path):
        """Parse HAR file exported from Charles Proxy"""
        try:
            with open(har_path, 'r', encoding='utf-8') as f:
                har_data = json.load(f)
            
            entries = har_data['log']['entries']
            requests = []
            
            for entry in entries:
                request = entry['request']
                response = entry['response']
                
                parsed_request = {
                    'method': request['method'],
                    'url': request['url'],
                    'headers': {h['name']: h['value'] for h in request['headers']},
                    'query_params': {},
                    'post_data': None,
                    'response_headers': {h['name']: h['value'] for h in response['headers']},
                    'response_body': None
                }
                
                # Parse URL parameters
                parsed_url = urlparse(request['url'])
                parsed_request['path'] = parsed_url.path
                parsed_request['query_params'] = parse_qs(parsed_url.query)
                
                # Parse POST data
                if 'postData' in request and request['postData']:
                    parsed_request['post_data'] = request['postData']
                
                # Get response body
                if 'text' in response['content']:
                    parsed_request['response_body'] = response['content']['text']
                
                requests.append(parsed_request)
            
            return requests
            
        except Exception as e:
            print(f"Error parsing HAR file: {e}")
            return []
    
    def parse_raw_http(self, raw_http):
        """Parse raw HTTP request/response text"""
        try:
            lines = raw_http.strip().split('\n')
            if not lines:
                return None
            
            # Parse request line
            request_line = lines[0].strip()
            method, path, version = request_line.split(' ', 2)
            
            # Parse headers
            headers = {}
            body_start = len(lines)
            
            for i, line in enumerate(lines[1:], 1):
                if line.strip() == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Parse body
            body = '\n'.join(lines[body_start:]) if body_start < len(lines) else None
            
            # Extract URL components
            parsed_url = urlparse(path)
            
            return {
                'method': method,
                'path': parsed_url.path,
                'query_params': parse_qs(parsed_url.query),
                'headers': headers,
                'body': body
            }
            
        except Exception as e:
            print(f"Error parsing raw HTTP: {e}")
            return None
    
    def generate_uri_patterns(self, requests):
        """Generate URI patterns from captured requests"""
        paths = [req['path'] for req in requests if req.get('path')]
        
        # Extract common patterns
        unique_paths = list(set(paths))
        
        # Generate variations
        uri_patterns = []
        for path in unique_paths[:5]:  # Limit to 5 patterns
            # Add original path
            uri_patterns.append(path)
            
            # Generate variations with parameters
            if '?' not in path:
                variations = [
                    f"{path}",
                    f"{path}/",
                    f"{path}/index.html",
                    f"{path}/api",
                    f"{path}/search"
                ]
                uri_patterns.extend(variations[:2])
        
        # Ensure we have at least some default patterns
        if not uri_patterns:
            uri_patterns = ["/search", "/api", "/index.html", "/images", "/css"]
        
        return uri_patterns[:8]  # Limit to 8 patterns
    
    def extract_common_headers(self, requests):
        """Extract common headers from requests"""
        header_counts = {}
        
        for req in requests:
            for header, value in req.get('headers', {}).items():
                if header.lower() not in ['content-length', 'content-encoding']:
                    header_counts[header] = header_counts.get(header, 0) + 1
        
        # Sort by frequency and return most common
        common_headers = sorted(header_counts.items(), key=lambda x: x[1], reverse=True)
        return [header for header, count in common_headers[:10]]
    
    def select_parameter_for_metadata(self, requests):
        """Select best parameter for metadata placement"""
        param_counts = {}
        
        for req in requests:
            for param_list in req.get('query_params', {}).values():
                for param in param_list:
                    if len(param) > 4:  # Prefer longer parameters
                        param_counts[param] = param_counts.get(param, 0) + 1
        
        if param_counts:
            # Return most common parameter
            return max(param_counts.items(), key=lambda x: x[1])[0]
        
        # Return a suitable parameter from common list
        return random.choice(self.common_params)
    
    def generate_http_get_block(self, requests):
        """Generate http-get block"""
        uri_patterns = self.generate_uri_patterns(requests)
        common_headers = self.extract_common_headers(requests)
        metadata_param = self.select_parameter_for_metadata(requests)
        
        # Get a sample request for reference
        sample_req = requests[0] if requests else {}
        
        # Generate client block
        client_headers = []
        for header in common_headers[:8]:
            if header.lower() in ['host', 'user-agent', 'accept', 'accept-language', 
                                'accept-encoding', 'connection', 'referer']:
                # Use actual values from captured traffic
                for req in requests:
                    if header in req.get('headers', {}):
                        value = req['headers'][header]
                        client_headers.append(f'        header "{header}" "{value}";')
                        break
        
        # Generate metadata block
        encoding = random.choice(self.cs_encodings)
        
        block = f'''http-get {{{{
    set uri "{' '.join(uri_patterns)}";
    
    client {{{{
{chr(10).join(client_headers)}
        
        metadata {{{{
            {encoding};
            parameter "{metadata_param}";
        }}}}
    }}}}
    
    server {{{{
        header "Server" "nginx/1.18.0";
        header "Content-Type" "text/html; charset=UTF-8";
        header "Connection" "keep-alive";
        header "Cache-Control" "no-cache, no-store, must-revalidate";
        
        output {{{{
            netbios;
            prepend "<!DOCTYPE html><html><head><title>Search Results</title></head><body>";
            append "</body></html>";
        }}}}
    }}}}
}}}}'''
        
        return block
    
    def generate_http_post_block(self, requests):
        """Generate http-post block"""
        post_requests = [req for req in requests if req.get('method') == 'POST']
        
        if not post_requests:
            # Generate default POST block
            uri_patterns = ["/submit", "/api/data", "/upload"]
        else:
            uri_patterns = self.generate_uri_patterns(post_requests)
        
        common_headers = self.extract_common_headers(post_requests or requests)
        
        # Generate client headers
        client_headers = []
        for header in common_headers[:8]:
            if header.lower() in ['host', 'user-agent', 'accept', 'content-type', 'referer']:
                for req in (post_requests or requests):
                    if header in req.get('headers', {}):
                        value = req['headers'][header]
                        client_headers.append(f'        header "{header}" "{value}";')
                        break
        
        # Select parameters for data placement
        id_param = random.choice(['id', 'sessionid', 'token', 'key'])
        output_param = random.choice(['data', 'content', 'response', 'result'])
        
        block = f'''http-post {{{{
    set uri "{' '.join(uri_patterns)}";
    
    client {{{{
{chr(10).join(client_headers)}
        
        id {{{{
            netbios;
            parameter "{id_param}";
        }}}}
        
        output {{{{
            base64;
            parameter "{output_param}";
        }}}}
    }}}}
    
    server {{{{
        header "Server" "nginx/1.18.0";
        header "Content-Type" "application/json";
        header "Connection" "keep-alive";
        
        output {{{{
            netbios;
            prepend "{{\\"status\\":\\"success\\",\\"data\\":\\"";
            append "\\"}}}}";
        }}}}
    }}}}
}}}}'''
        
        return block
    
    def generate_http_stager_block(self, requests):
        """Generate http-stager block"""
        uri_patterns = self.generate_uri_patterns(requests)
        common_headers = self.extract_common_headers(requests)
        
        # Generate client headers for stager
        client_headers = []
        essential_headers = ['host', 'user-agent', 'accept', 'accept-encoding']
        
        for header in essential_headers:
            for req in requests:
                req_headers = {k.lower(): v for k, v in req.get('headers', {}).items()}
                if header in req_headers:
                    value = req_headers[header]
                    client_headers.append(f'        header "{header.title()}" "{value}";')
                    break
        
        block = f'''http-stager {{{{
    set uri_x86 "{uri_patterns[0] if uri_patterns else '/api/x86'}";
    set uri_x64 "{uri_patterns[1] if len(uri_patterns) > 1 else '/api/x64'}";
    
    client {{{{
{chr(10).join(client_headers)}
    }}}}
    
    server {{{{
        header "Server" "nginx/1.18.0";
        header "Content-Type" "application/octet-stream";
        header "Connection" "keep-alive";
        
        output {{{{
            prepend "<!DOCTYPE html><html><body>";
            append "</body></html>";
        }}}}
    }}}}
}}}}'''
        
        return block
    
    def generate_http_config_block(self, requests):
        """Generate http-config block"""
        # Extract headers for configuration
        sample_headers = {}
        if requests:
            sample_headers = requests[0].get('headers', {})
        
        # Common headers to set
        user_agent = sample_headers.get('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        
        block = f'''http-config {{{{
    set headers "Date, Server, Content-Length, Keep-Alive, Connection, Content-Type";
    set headers_remove "Server, X-Powered-By, X-AspNet-Version";
    
    set trust_x_forwarded_for "false";
    set block_useragents "curl*, HTTPie*, wget*, python-requests*";
}}}}'''
        
        return block
    
    def generate_full_profile(self, requests, profile_name="Generated Profile"):
        """Generate complete CS profile"""
        http_config = self.generate_http_config_block(requests)
        http_get = self.generate_http_get_block(requests)
        http_post = self.generate_http_post_block(requests)
        http_stager = self.generate_http_stager_block(requests)
        
        # Extract user agent for global setting
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        if requests and requests[0].get('headers', {}).get('User-Agent'):
            user_agent = requests[0]['headers']['User-Agent']
        
        profile = f'''#
# {profile_name}
# Generated from Charles Proxy capture
#

set sample_name "{profile_name}";
set sleeptime "30000";
set jitter "20";
set useragent "{user_agent}";

{http_config}

{http_get}

{http_post}

{http_stager}

# HTTPS beacon (mirrors HTTP)
https-beacon {{
    # Copy http-get settings
    set uri "{' '.join(self.generate_uri_patterns(requests))}";
    
    client {{
        # Add SSL-specific headers
        header "Upgrade-Insecure-Requests" "1";
    }}
}}'''
        
        return profile

def main():
    parser = argparse.ArgumentParser(description='Convert Charles Proxy captures to Cobalt Strike profiles')
    parser.add_argument('input', help='Input file (HAR or raw HTTP)')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument('-n', '--name', default='Generated Profile', help='Profile name')
    parser.add_argument('-f', '--format', choices=['har', 'raw'], help='Input format (auto-detect if not specified)')
    parser.add_argument('--block', choices=['http-get', 'http-post', 'http-stager', 'http-config', 'full'], 
                       default='full', help='Generate specific block only')
    
    args = parser.parse_args()
    
    converter = CharlesToCSConverter()
    
    # Determine input format
    input_format = args.format
    if not input_format:
        if args.input.lower().endswith('.har'):
            input_format = 'har'
        else:
            input_format = 'raw'
    
    # Parse input
    if input_format == 'har':
        requests = converter.parse_har_file(args.input)
    else:
        with open(args.input, 'r') as f:
            raw_data = f.read()
        parsed = converter.parse_raw_http(raw_data)
        requests = [parsed] if parsed else []
    
    if not requests:
        print("No valid requests found in input", file=sys.stderr)
        sys.exit(1)
    
    print(f"Parsed {len(requests)} requests", file=sys.stderr)
    
    # Generate output
    if args.block == 'full':
        output = converter.generate_full_profile(requests, args.name)
    elif args.block == 'http-get':
        output = converter.generate_http_get_block(requests)
    elif args.block == 'http-post':
        output = converter.generate_http_post_block(requests)
    elif args.block == 'http-stager':
        output = converter.generate_http_stager_block(requests)
    elif args.block == 'http-config':
        output = converter.generate_http_config_block(requests)
    
    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Profile written to {args.output}", file=sys.stderr)
    else:
        print(output)

if __name__ == '__main__':
    main()
