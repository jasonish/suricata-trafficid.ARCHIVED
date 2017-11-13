all: rules/appid.rules

rules/appid.rules: appid.yaml appid.py
	mkdir -p rules
	./appid.py -o $@ gen
