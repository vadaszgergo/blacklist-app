from flask import Flask, render_template, request
import ipaddress

app = Flask(__name__)

def parse_ip_range(ip_range):
    try:
        ip_network = ipaddress.ip_network(ip_range)
        return ip_network
    except ValueError:
        return None

def create_complementary_blacklist(whitelist):
    complementary_blacklist = []
    all_ips_v4 = ipaddress.ip_network('0.0.0.0/0')
    all_ips_v6 = ipaddress.ip_network('::/0')

    # Create the blacklist for both IPv4 and IPv6 by finding the complementary ranges
    for whitelisted_range in whitelist:
        if whitelisted_range.version == 4:
            complementary_range = all_ips_v4.address_exclude(whitelisted_range)
            complementary_blacklist.extend(complementary_range)
        elif whitelisted_range.version == 6:
            complementary_range = all_ips_v6.address_exclude(whitelisted_range)
            complementary_blacklist.extend(complementary_range)

    return complementary_blacklist

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        whitelist_ipv4 = request.form.get('whitelist_ipv4')
        whitelist_ipv4 = whitelist_ipv4.split('\n')
        parsed_whitelist_ipv4 = [parse_ip_range(ip_range) for ip_range in whitelist_ipv4 if parse_ip_range(ip_range) is not None]
        blacklist_ipv4 = create_complementary_blacklist(parsed_whitelist_ipv4)

        whitelist_ipv6 = request.form.get('whitelist_ipv6')
        whitelist_ipv6 = whitelist_ipv6.split('\n')
        parsed_whitelist_ipv6 = [parse_ip_range(ip_range) for ip_range in whitelist_ipv6 if parse_ip_range(ip_range) is not None]
        blacklist_ipv6 = create_complementary_blacklist(parsed_whitelist_ipv6)

        return render_template('index.html', whitelist_ipv4=whitelist_ipv4, whitelist_ipv6=whitelist_ipv6,
                               blacklist_ipv4=blacklist_ipv4, blacklist_ipv6=blacklist_ipv6)
    else:
        return render_template('index.html', whitelist_ipv4=[], whitelist_ipv6=[], blacklist_ipv4=[], blacklist_ipv6=[])

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
