FROM	opensuse/tumbleweed
# change this to Leap once they update to Python 3.7 or higher

# Copy project
COPY . /app

# Prep environment
ENV	ZYPPER_PACKAGES="python39-pip"

RUN	zypper ref && zypper --non-interactive install $ZYPPER_PACKAGES


ENTRYPOINT	["/app/main.py"]
