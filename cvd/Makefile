test: clean
	docker build -t clamav:latest .
	docker run --name clamav -e SERVER -e KEY -e SECRET clamav:latest

clean:
	docker system prune -f