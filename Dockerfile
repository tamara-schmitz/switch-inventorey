FROM	opensuse/tumbleweed
# change this to Leap once they update to Python 3.7 or higher

# Prep environment
ENV	ZYPPER_PACKAGES="net-snmp-devel gcc \
		graphviz graphviz-gd patterns-fonts-fonts \
		python39 python39-devel python39-pip python39-graphviz"

RUN	zypper ref && \
	zypper --non-interactive install $ZYPPER_PACKAGES && \
	zypper clean && \
	update-alternatives --install /usr/bin/python python \
	/usr/bin/python3.9 1 && \
	update-alternatives --install /usr/bin/python3 python3 \
	/usr/bin/python3.9 1 && \
	pip3 install easysnmp


# Copy project
COPY . /app

ENTRYPOINT	["/app/main.py"]
