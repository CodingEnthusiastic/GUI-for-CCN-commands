import subprocess

def run_command(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
        return output.strip()
    except subprocess.CalledProcessError:
        return "N/A"

def activity1():
    capture_file = "capture.pcap"
    print("=== Activity 1 Final Answers ===")

    browser_http_version = run_command(f'tshark -r {capture_file} -Y "http.request" -T fields -e http.request.version | head -n 1')
    print("Q1. Browser HTTP Version (Request):", browser_http_version)

    server_http_version = run_command(f'tshark -r {capture_file} -Y "http.response" -T fields -e http.response.version | head -n 1')
    print("Q2. Server HTTP Version (Response):", server_http_version)

    accept_language = run_command(f'tshark -r {capture_file} -Y "http.request" -T fields -e http.accept_language | head -n 1')
    print("Q3. Accept-Language header:", accept_language)

    user_agent = run_command(f'tshark -r {capture_file} -Y "http.request" -T fields -e http.user_agent | head -n 1')
    print("Q4. User-Agent header:", user_agent)

    client_ip = run_command(f'tshark -r {capture_file} -Y "http" -T fields -e ip.src | head -n 1')
    print("Q5. Client IP Address:", client_ip)

    server_ip = run_command(f'tshark -r {capture_file} -Y "http" -T fields -e ip.dst | head -n 1')
    print("Q6. Server IP Address:", server_ip)

    status_code = run_command(f'tshark -r {capture_file} -Y "http.response" -T fields -e http.response.code -e http.response.phrase | head -n 1')
    print("Q7. HTTP Response Status Code and Phrase:", status_code)

    last_modified = run_command(f'tshark -r {capture_file} -Y "http.response" -T fields -e http.last_modified | head -n 1')
    print("Q8. Last-Modified header:", last_modified)

    content_length = run_command(f'tshark -r {capture_file} -Y "http.response" -T fields -e http.content_length | head -n 1')
    print("Q9. Content-Length header:", content_length)

    connection = run_command(f'tshark -r {capture_file} -Y "http" -T fields -e http.connection -c 1')
    if connection and connection != "N/A":
        print("Q10. Extra HTTP header (Connection):", connection)
    else:
        print("Q10. No extra HTTP headers found.")
    print("-" * 60)

def activity2():
    capture_file = "capture2.pcap"
    print("=== Activity 2 Final Answers ===")

    cmd_get_frames = f'tshark -r {capture_file} -Y "http.request.method == GET" -T fields -e frame.number'
    get_frames_output = run_command(cmd_get_frames)
    get_frames = get_frames_output.splitlines()
    if len(get_frames) < 1:
        q1_ans = "No HTTP GET requests found in the capture."
    else:
        first_get_frame = get_frames[0]
        cmd_first_get = f'tshark -r {capture_file} -Y "frame.number == {first_get_frame}" -V'
        first_get_details = run_command(cmd_first_get)
        if "If-Modified-Since:" in first_get_details:
            q1_ans = "Yes, the first GET request includes an 'If-Modified-Since' header (unexpected)."
        else:
            q1_ans = "No, the first GET request does NOT include an 'If-Modified-Since' header."
    print("Q1. First HTTP GET request - 'If-Modified-Since' present?:", q1_ans)

    cmd_resp_frames = f'tshark -r {capture_file} -Y "http.response" -T fields -e frame.number'
    resp_frames_output = run_command(cmd_resp_frames)
    resp_frames = resp_frames_output.splitlines()
    if len(resp_frames) < 1:
        q2_ans = "No HTTP responses found in the capture."
    else:
        first_resp_frame = resp_frames[0]
        cmd_first_resp = f'tshark -r {capture_file} -Y "frame.number == {first_resp_frame}" -V'
        first_resp_details = run_command(cmd_first_resp)
        if "200 OK" in first_resp_details:
            q2_ans = "Yes, the server explicitly returned the file (200 OK with content)."
        else:
            q2_ans = "No, the server did not explicitly return the file (response may be 304 Not Modified)."
    print("Q2. Server response to first GET request:", q2_ans)

def activity3():
    capture_file = "capture3.pcap"
    print("=== Activity 3 Final Answers ===")

    cmd_q1 = f'tshark -r {capture_file} -Y "http.request.method == GET" -T fields -e frame.number'
    get_frames_output = run_command(cmd_q1)
    get_requests_count = len(get_frames_output.splitlines()) if get_frames_output else 0
    print("Q1. Number of HTTP GET requests sent by the browser:", get_requests_count)

    cmd_q2 = f'tshark -r {capture_file} -Y "http.response" -T fields -e tcp.segment | head -n 1'
    tcp_segments_field = run_command(cmd_q2)
    segments = tcp_segments_field.split(',') if tcp_segments_field and tcp_segments_field != "N/A" else []
    tcp_segments_count = len(segments)
    print("Q2. Number of data-containing TCP segments for the HTTP response:", tcp_segments_count)

    cmd_q3 = f'tshark -r {capture_file} -Y "http.response" -T fields -e http.response.code -e http.response.phrase | head -n 1'
    status_response = run_command(cmd_q3)
    print("Q3. HTTP Response Status Code and Phrase:", status_response)

    header_segmentation_info = "No, TCP segmentation is performed at the transport layer and does not add extra HTTP header information."
    print("Q4.", header_segmentation_info)
    print("-" * 60)

def activity4():
    capture_file = "capture4.pcap"
    print("=== Activity 4 Final Answers ===")

    cmd_get = f'tshark -r {capture_file} -Y "http.request.method == GET" -T fields -e frame.time_relative -e http.request.uri'
    get_output = run_command(cmd_get)
    get_lines = [line.strip() for line in get_output.splitlines() if line.strip()]
    print("All GET requests (relative time and URI):")
    for idx, line in enumerate(get_lines, start=1):
        print(f" {idx}. {line}")

    if len(get_lines) < 3:
        print("\nError: Less than three GET requests found; cannot analyze image download mode.")
    else:
        second_line = get_lines[1]
        third_line = get_lines[2]
        try:
            t2 = float(second_line.split()[0])
            t3 = float(third_line.split()[0])
            time_diff = abs(t3 - t2)
        except Exception:
            time_diff = None

        threshold = 0.1
        if time_diff is not None:
            if time_diff < threshold:
                mode = "parallel"
                explanation = (f"2nd GET at {t2:.3f} sec, 3rd GET at {t3:.3f} sec - less than {threshold} sec apart")
            else:
                mode = "sequential"
                explanation = (f"2nd GET at {t2:.3f} sec, 3rd GET at {t3:.3f} sec - more than {threshold} sec apart")
            print(f"\nImage download mode: {mode}")
            print(f"Explanation: {explanation}")
    print("-" * 60)

def activity5():
    capture_file = "capture5.pcap"
    print("=== Activity 5 Final Answers ===")

    # Q1: Find the total number of HTTP requests in the capture
    cmd_q1 = f'tshark -r {capture_file} -Y "http.request" -T fields -e frame.number'
    http_requests_output = run_command(cmd_q1)
    http_requests_count = len(http_requests_output.splitlines()) if http_requests_output else 0
    print("Q1. Total number of HTTP requests:", http_requests_count)

    # Q2: Find the total number of TCP retransmissions
    cmd_q2 = f'tshark -r {capture_file} -Y "tcp.analysis.retransmission" -T fields -e frame.number'
    retransmissions_output = run_command(cmd_q2)
    retransmissions_count = len(retransmissions_output.splitlines()) if retransmissions_output else 0
    print("Q2. Total number of TCP retransmissions:", retransmissions_count)

    # Q3: Find the most common User-Agent string in the capture
    cmd_q3 = f'tshark -r {capture_file} -Y "http.request" -T fields -e http.user_agent'
    user_agents_output = run_command(cmd_q3)
    user_agents = [line.strip() for line in user_agents_output.splitlines() if line.strip()]
    if user_agents:
        most_common_user_agent = max(set(user_agents), key=user_agents.count)
    else:
        most_common_user_agent = "N/A"
    print("Q3. Most common User-Agent:", most_common_user_agent)

    # Q4: Check if there are any HTTP 404 Not Found responses
    cmd_q4 = f'tshark -r {capture_file} -Y "http.response.code == 404" -T fields -e frame.number'
    not_found_output = run_command(cmd_q4)
    has_404_errors = "Yes" if not_found_output else "No"
    print("Q4. Are there any 404 Not Found responses?", has_404_errors)

    print("-" * 60)

def main():
    print("=== Network Capture Analysis ===\n")
    activity1()
    activity2()
    activity3()
    activity4()
    activity5()
    print("\n=== End of Analysis ===")

if __name__ == "__main__":
    main()
