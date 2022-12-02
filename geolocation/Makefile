test: clean
	docker build -t geoip:latest .
	docker run --name geoip -e SERVER -e ASN -e BLOCK -e KEY -e SECRET geoip:latest

clean:
	docker system prune -f