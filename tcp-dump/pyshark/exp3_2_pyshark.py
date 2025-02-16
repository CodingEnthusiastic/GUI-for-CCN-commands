import pyshark

def activity1():
    capture_file = "capture.pcap"
    print("=== Activity 1 Final Answers ===")
    cap = pyshark.FileCapture(capture_file, display_filter="http")

    browser_http_version = "N/A"
    for pkt in cap:
        if hasattr(pkt.http, 'request_method'):
            browser_http_version = getattr(pkt.http, 'request_version', "N/A")
            break
    print("Q1. Browser HTTP Version (Request):", browser_http_version)

    server_http_version = "N/A"
    for pkt in cap:
        if hasattr(pkt.http, 'response_code'):
            server_http_version = getattr(pkt.http, 'response_version', "N/A")
            break
    print("Q2. Server HTTP Version (Response):", server_http_version)

    accept_language = "N/A"
    for pkt in cap:
        if hasattr(pkt.http, 'request_method') and hasattr(pkt.http, 'accept_language'):
            accept_language = pkt.http.accept_language
            break
    print("Q3. Accept-Language header:", accept_language)

    user_agent = "N/A"
    for pkt in cap:
        if hasattr(pkt.http, 'request_method') and hasattr(pkt.http, 'user_agent'):
            user_agent = pkt.http.user_agent
            break
    print("Q4. User-Agent header:", user_agent)

    client_ip = "N/A"
    for pkt in cap:
        if hasattr(pkt, 'ip'):
            client_ip = pkt.ip.src
            break
    print("Q5. Client IP Address:", client_ip)

    server_ip = "N/A"
    for pkt in cap:
        if hasattr(pkt, 'ip'):
            server_ip = pkt.ip.dst
            break
    print("Q6. Server IP Address:", server_ip)

    status_response = "N/A"
    for pkt in cap:
        if hasattr(pkt.http, 'response_code'):
            status_response = f"{pkt.http.response_code} {getattr(pkt.http, 'response_phrase', '')}"
            break
    print("Q7. HTTP Response Status Code and Phrase:", status_response)

    last_modified = "N/A"
    for pkt in cap:
        if hasattr(pkt.http, 'last_modified'):
            last_modified = pkt.http.last_modified
            break
    print("Q8. Last-Modified header:", last_modified)

    content_length = "N/A"
    for pkt in cap:
        if hasattr(pkt.http, 'content_length'):
            content_length = pkt.http.content_length
            break
    print("Q9. Content-Length header:", content_length)

    cap.close()
    print("-" * 60)

def activity2():
    capture_file = "capture2.pcap"
    print("=== Activity 2 Final Answers ===")
    cap = pyshark.FileCapture(capture_file, display_filter="http")
    
    get_packets = [pkt for pkt in cap if hasattr(pkt.http, 'request_method')]
    if len(get_packets) < 1:
        q1_ans = "No HTTP GET requests found in the capture."
    else:
        first_get = get_packets[0]
        if hasattr(first_get.http, 'if_modified_since'):
            q1_ans = "Yes, it includes 'If-Modified-Since': " + first_get.http.if_modified_since
        else:
            q1_ans = "No, it does not include 'If-Modified-Since'."
    print("Q1. First HTTP GET request - 'If-Modified-Since' present?:", q1_ans)

    response_packets = [pkt for pkt in cap if hasattr(pkt.http, 'response_code')]
    if len(response_packets) < 1:
        q2_ans = "No HTTP responses found in the capture."
    else:
        first_resp = response_packets[0]
        if first_resp.http.response_code == "200":
            q2_ans = "Yes, server returned file (200 OK with content)."
        else:
            q2_ans = "No, server did not explicitly return file (response might be 304 Not Modified)."
    print("Q2. Server response to first GET request:", q2_ans)

    if len(get_packets) < 3:
        q3_ans = "Less than three HTTP GET requests found in the capture."
    else:
        second_get = get_packets[2]
        if hasattr(second_get.http, 'if_modified_since'):
            q3_ans = "Yes, includes 'If-Modified-Since': " + second_get.http.if_modified_since
        else:
            q3_ans = "No, it does not include 'If-Modified-Since'."
    print("Q3. Second HTTP GET request 'If-Modified-Since' header:", q3_ans)

    if len(response_packets) < 3:
        q4_ans = "Less than three HTTP responses found in the capture."
    else:
        second_resp = response_packets[2]
        if second_resp.http.response_code == "304":
            q4_ans = "304 Not Modified - file not returned; use cache."
        elif second_resp.http.response_code == "200":
            q4_ans = "200 OK - file was explicitly returned."
        else:
            q4_ans = "Unable to determine response status."
    print("Q4. Server response to second GET request:", q4_ans)

    cap.close()
    print("-" * 60)

def activity3():
    capture_file = "capture3.pcap"
    print("=== Activity 3 Final Answers ===")
    cap = pyshark.FileCapture(capture_file, display_filter="http")
    
    get_requests = [pkt for pkt in cap if hasattr(pkt.http, 'request_method')]
    num_get_requests = len(get_requests)
    print("Q1. Number of HTTP GET requests sent by the browser:", num_get_requests)

    tcp_segments_count = -1
    response_packets = [pkt for pkt in cap if hasattr(pkt.http, 'response_code')]
    if response_packets:
        first_resp = response_packets[0]
        if hasattr(first_resp, 'tcp') and hasattr(first_resp.tcp, 'stream'):
            stream_no = first_resp.tcp.stream
            stream_cap = pyshark.FileCapture(capture_file, display_filter=f'tcp.stream == {stream_no}')
            for pkt in stream_cap:
                if hasattr(pkt, 'tcp'):
                    try:
                        tcp_len = int(pkt.tcp.len)
                    except (AttributeError, ValueError):
                        tcp_len = 0
                    if tcp_len > 0:
                        tcp_segments_count += 1
            stream_cap.close()
    print("Q2. Number of data-containing TCP segments for the HTTP response:", tcp_segments_count)

    status_response = "N/A"
    if response_packets:
        first_resp = response_packets[0]
        try:
            status_response = f"{first_resp.http.response_code} {first_resp.http.response_phrase}"
        except AttributeError:
            status_response = "N/A"
    print("Q3. HTTP Response Status Code and Phrase:", status_response)

    header_segmentation_info = ("No, TCP segmentation is performed at the transport layer and does not add extra HTTP header information.")
    print("Q4.", header_segmentation_info)
    
    cap.close()
    print("-" * 60)

def main():
    activity1()
    activity2()
    activity3()

if __name__ == "__main__":
    main()
