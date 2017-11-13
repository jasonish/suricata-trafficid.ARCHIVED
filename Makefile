all: rules/traffic-id.rules

rules/traffic-id.rules: traffic-id.yaml traffic-id.py
	mkdir -p rules
	./traffic-id.py -o $@ gen
