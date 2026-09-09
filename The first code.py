import re
from urllib.parse import urlsplit, parse_qsl


SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "x-api-key",
    "proxy-authorization",
}

SECURITY_HEADERS = {
    "host": "Identifies the target host. Important for virtual hosting and host-header handling.",
    "origin": "Indicates the origin that initiated the request. Important when investigating CORS and CSRF-related behavior.",
    "referer": "Shows the referring URL. May reveal sensitive URL information.",
    "user-agent": "Identifies the client software. Useful for fingerprinting and behavior analysis.",
    "content-type": "Describes the request body format, such as form data or JSON.",
    "content-length": "Specifies the size of the request body.",
    "authorization": "Carries authentication credentials or tokens. Highly sensitive.",
    "cookie": "Carries browser/session state. May contain authentication or tracking information.",
    "x-api-key": "Commonly used for API authentication. Sensitive if present.",
    "x-forwarded-for": "May contain the original client IP when proxies are used. Important when investigating trusted-proxy behavior.",
    "x-forwarded-host": "May influence the host seen by an application behind a proxy.",
    "x-forwarded-proto": "Indicates the original protocol used by the client.",
    "content-security-policy": "Normally a response header, so its presence in a request is unusual and worth noting.",
}


def parse_http_request(raw_request):
    """
    Parse a raw HTTP request into method, target, headers, cookies and body.
    """

    raw_request = raw_request.replace("\r\n", "\n")

    parts = raw_request.split("\n\n", 1)

    request_head = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    lines = request_head.split("\n")

    if not lines:
        raise ValueError("Empty HTTP request.")

    request_line = lines[0].strip()

    request_match = re.match(
        r"^([A-Z]+)\s+(\S+)\s+HTTP/(\d(?:\.\d)?)$",
        request_line
    )

    if not request_match:
        raise ValueError(
            "Invalid HTTP request line. Expected format: "
            "METHOD /path HTTP/1.1"
        )

    method = request_match.group(1)
    target = request_match.group(2)
    http_version = request_match.group(3)

    headers = {}

    for line in lines[1:]:
        if ":" not in line:
            continue

        name, value = line.split(":", 1)

        name = name.strip().lower()
        value = value.strip()

        headers[name] = value

    return {
        "method": method,
        "target": target,
        "http_version": http_version,
        "headers": headers,
        "body": body,
    }


def analyze_method(method):
    explanations = {
        "GET": (
            "GET is normally used to retrieve a resource. "
            "It should generally not be used to perform state-changing actions."
        ),
        "POST": (
            "POST is commonly used to submit data or request a server-side "
            "operation that may change application state."
        ),
        "PUT": (
            "PUT is commonly used to create or completely replace a resource "
            "at a specified location."
        ),
        "PATCH": (
            "PATCH is normally used to partially modify an existing resource."
        ),
        "DELETE": (
            "DELETE is normally used to request deletion of a resource."
        ),
        "HEAD": (
            "HEAD requests the same headers as a GET request without normally "
            "returning the response body."
        ),
        "OPTIONS": (
            "OPTIONS asks the server which communication options are available "
            "for a resource."
        ),
        "TRACE": (
            "TRACE is intended for diagnostic purposes and can reflect a request "
            "back to the client."
        ),
        "CONNECT": (
            "CONNECT is commonly used to establish a tunnel, such as an HTTPS "
            "tunnel through a proxy."
        ),
    }

    return explanations.get(
        method,
        "This is a non-standard or less common HTTP method."
    )


def analyze_target(target):
    """
    Analyze path, query parameters and URL components.
    """

    parsed = urlsplit(target)

    path = parsed.path or "/"
    query = parsed.query

    query_parameters = parse_qsl(
        query,
        keep_blank_values=True
    )

    return {
        "scheme": parsed.scheme,
        "netloc": parsed.netloc,
        "path": path,
        "query": query,
        "fragment": parsed.fragment,
        "query_parameters": query_parameters,
    }


def analyze_headers(headers):
    findings = []

    for name, value in headers.items():

        description = SECURITY_HEADERS.get(
            name,
            "General HTTP header. Its exact security significance depends on the application."
        )

        if name in SENSITIVE_HEADERS:
            sensitivity = "HIGH SENSITIVITY"
        else:
            sensitivity = "NORMAL"

        findings.append({
            "name": name,
            "value": value,
            "sensitivity": sensitivity,
            "description": description,
        })

    return findings


def analyze_cookies(headers):
    cookie_header = headers.get("cookie")

    if not cookie_header:
        return []

    cookies = []

    for item in cookie_header.split(";"):
        item = item.strip()

        if "=" not in item:
            continue

        name, value = item.split("=", 1)

        cookies.append({
            "name": name.strip(),
            "value": value.strip(),
            "purpose": (
                "May represent session state, authentication state, "
                "preferences, tracking information, or application data. "
                "The exact purpose must be determined from the application."
            )
        })

    return cookies


def analyze_body(body, headers):
    if not body:
        return {
            "present": False,
            "content_type": None,
            "parameters": []
        }

    content_type = headers.get("content-type", "").lower()

    parameters = []

    if "application/x-www-form-urlencoded" in content_type:

        for key, value in parse_qsl(
            body,
            keep_blank_values=True
        ):
            parameters.append({
                "name": key,
                "value": value
            })

    elif "application/json" in content_type:

        parameters.append({
            "name": "JSON body",
            "value": body
        })

    elif "multipart/form-data" in content_type:

        parameters.append({
            "name": "Multipart body",
            "value": body
        })

    else:

        parameters.append({
            "name": "Raw body",
            "value": body
        })

    return {
        "present": True,
        "content_type": content_type or "Not specified",
        "parameters": parameters
    }


def analyze_authentication(headers):
    indicators = []

    if "authorization" in headers:
        indicators.append(
            "Authorization header observed. This may indicate HTTP authentication "
            "or token-based authentication."
        )

    if "cookie" in headers:
        indicators.append(
            "Cookie header observed. It may contain a session identifier or "
            "authentication-related state."
        )

    if "x-api-key" in headers:
        indicators.append(
            "X-API-Key header observed. This may indicate API-key authentication."
        )

    if not indicators:
        indicators.append(
            "No obvious authentication indicator was observed in the request. "
            "This does NOT prove that the endpoint is unauthenticated."
        )

    return indicators


def identify_points_of_interest(
    method,
    target_info,
    headers,
    body_info
):
    points = []

    path = target_info["path"].lower()

    sensitive_path_words = [
        "admin",
        "login",
        "auth",
        "account",
        "user",
        "password",
        "token",
        "api",
        "upload",
        "delete",
        "debug",
        "config",
        "internal",
    ]

    for word in sensitive_path_words:
        if word in path:
            points.append(
                f"Path contains '{word}'. This is a point of interest for "
                f"authorized testing, but it is NOT evidence of a vulnerability."
            )

    if method in {"PUT", "PATCH", "DELETE"}:
        points.append(
            f"{method} can modify or delete server-side resources. "
            "Authorization and access-control behavior should be verified."
        )

    if "authorization" in headers:
        points.append(
            "Authentication token is present. In an authorized environment, "
            "its validation, expiration, scope and access-control behavior "
            "may be worth reviewing."
        )

    if "cookie" in headers:
        points.append(
            "Session-related state may be present in cookies. "
            "Cookie handling and session lifecycle can be reviewed."
        )

    if "origin" in headers:
        points.append(
            "Origin header is present. CORS behavior may be worth reviewing "
            "against the server's actual response."
        )

    if "x-forwarded-for" in headers:
        points.append(
            "X-Forwarded-For is present. Review whether the application "
            "correctly trusts proxy-provided client IP information."
        )

    if "x-forwarded-host" in headers:
        points.append(
            "X-Forwarded-Host is present. Review proxy/application handling "
            "if host information influences application behavior."
        )

    if target_info["query_parameters"]:
        points.append(
            "Query parameters are present. Their validation, authorization "
            "and input handling can be reviewed in the authorized environment."
        )

    if body_info["present"]:
        points.append(
            "A request body is present. Input validation and server-side "
            "handling can be reviewed."
        )

    return points


def print_section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def display_analysis(request_data):
    method = request_data["method"]
    target = request_data["target"]
    http_version = request_data["http_version"]
    headers = request_data["headers"]
    body = request_data["body"]

    target_info = analyze_target(target)
    header_info = analyze_headers(headers)
    cookies = analyze_cookies(headers)
    body_info = analyze_body(body, headers)
    auth_info = analyze_authentication(headers)

    points = identify_points_of_interest(
        method,
        target_info,
        headers,
        body_info
    )

    print_section("HTTP REQUEST ANALYSIS")

    print("\n[1] HTTP METHOD")
    print(f"Method: {method}")
    print(f"Purpose: {analyze_method(method)}")

    print_section("[2] URL / PATH")

    print(f"Original target: {target}")
    print(f"Scheme: {target_info['scheme'] or 'Not specified'}")
    print(f"Host/Network location: {target_info['netloc'] or 'Taken from Host header'}")
    print(f"Path: {target_info['path']}")
    print(f"Fragment: {target_info['fragment'] or 'None'}")

    print("\nSimple explanation:")
    print(
        "The path identifies which resource or endpoint the client is requesting."
    )

    print_section("[3] QUERY PARAMETERS")

    if target_info["query_parameters"]:
        for key, value in target_info["query_parameters"]:
            print(f"- {key} = {value}")
    else:
        print("No query parameters observed.")

    print("\nSimple explanation:")
    print(
        "Query parameters are values placed after '?' in the URL and are "
        "commonly used to provide filters, IDs, searches, pagination, etc."
    )

    print_section("[4] HTTP HEADERS")

    if not header_info:
        print("No headers observed.")
    else:
        for header in header_info:
            print(f"\n{header['name']}: {header['value']}")
            print(f"Sensitivity: {header['sensitivity']}")
            print(f"Security significance: {header['description']}")

    print_section("[5] COOKIES")

    if cookies:
        for cookie in cookies:
            print(f"\nCookie: {cookie['name']}")
            print(f"Value: {cookie['value']}")
            print(f"Purpose: {cookie['purpose']}")
    else:
        print("No Cookie header observed.")

    print_section("[6] REQUEST BODY")

    if not body_info["present"]:
        print("No request body observed.")
    else:
        print(f"Content-Type: {body_info['content_type']}")

        for parameter in body_info["parameters"]:
            print(
                f"- {parameter['name']} = {parameter['value']}"
            )

    print_section("[7] AUTHENTICATION / AUTHORIZATION")

    for item in auth_info:
        print(f"- {item}")

    print(
        "\nImportant: observing an Authorization header, cookie, API key, "
        "or similar value does not prove that authentication or authorization "
        "is secure or insecure."
    )

    print_section("[8] SECURITY POINTS OF INTEREST")

    if points:
        for point in points:
            print(f"- {point}")
    else:
        print(
            "No obvious points of interest were identified from the request alone."
        )

    print_section("[9] SIMPLE REQUEST SUMMARY")

    print(f"""
Method:
  {method}

Target:
  {target_info['path']}

Query parameters:
  {len(target_info['query_parameters'])}

Headers:
  {len(headers)}

Cookies:
  {len(cookies)}

Request body:
  {"Present" if body_info["present"] else "Not present"}

Authentication indicators:
  {"Present" if ("authorization" in headers or "cookie" in headers or "x-api-key" in headers) else "Not obvious"}
""")

    print_section("[10] IMPORTANT SECURITY DISCLAIMER")

    print(
        "This script performs request analysis only.\n"
        "It does NOT prove the existence of a vulnerability.\n\n"
        "For example:\n"
        "- A parameter does not automatically mean SQL Injection.\n"
        "- A Cookie does not automatically mean session vulnerability.\n"
        "- An Authorization header does not automatically mean broken authentication.\n"
        "- X-Forwarded-For does not automatically mean IP spoofing is possible.\n"
        "- An admin endpoint does not automatically mean unauthorized access exists.\n\n"
        "Any suspected issue must be verified through controlled testing "
        "against an authorized target."
    )


def main():
    print("=" * 70)
    print("HTTP REQUEST SECURITY ANALYZER")
    print("Authorized Lab / Defensive Analysis Tool")
    print("=" * 70)

    print(
        "\nPaste the raw HTTP request below."
        "\nFinish the input with an empty line."
        "\n"
    )

    lines = []

    while True:
        try:
            line = input()
        except EOFError:
            break

        if line == "":
            break

        lines.append(line)

    raw_request = "\n".join(lines)

    if not raw_request.strip():
        print("No HTTP request was provided.")
        return

    try:
        request_data = parse_http_request(raw_request)
        display_analysis(request_data)

    except ValueError as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()
