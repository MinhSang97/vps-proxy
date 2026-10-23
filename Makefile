-include .env

BIN  := proxy
NGROK      = $(if $(wildcard ./ngrok),./ngrok,ngrok)
NGROK_CFG  ?= $(HOME)/.config/ngrok/ngrok.yml
BORE       = $(if $(wildcard ./bore),./bore,bore)
BORE_URL   := https://github.com/ekzhang/bore/releases/download/v0.6.0/bore-v0.6.0-x86_64-unknown-linux-musl.tar.gz
BORE_PORT  ?= 40000
MONGO_NAME ?= vps-proxy-mongo
MONGO_PORT ?= 27017
MONGO_IMG  ?= mongo:7
HTTP_ADDR  ?= :8080
HTTP_PORT  := $(lastword $(subst :, ,$(HTTP_ADDR)))
VPS  ?= root@your-vps-ip
DIR  ?= /opt/proxy

run-proxy:      ## chay truc tiep file proxy.go, doc .env trong thu muc nay
	go run .

build:          ## build binary cho may nay
	go build -o $(BIN) .

dumpread:       ## build tool doc log: ./dumpread proxy.log
	go build -o dumpread ./cmd/dumpread

test:           ## chay test
	go test ./...

deploy: test    ## build cho linux amd64 roi day len VPS va restart service
	GOOS=linux GOARCH=amd64 go build -o $(BIN) .
	ssh $(VPS) mkdir -p $(DIR)
	rsync -av $(BIN) .env $(VPS):$(DIR)/
	ssh $(VPS) systemctl restart proxy

ngrok-local:    ## tai ngrok ban moi ve thu muc nay neu chua co
	@test -x ./ngrok || { echo "tai ngrok ban moi..."; curl -sL https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz | tar xz ngrok && echo "xong: $$(./ngrok --version)"; }

ngrok-setup:    ## khai token ngrok (make up tu goi)
	@test -n "$(NGROK_TOKEN)" || { echo "thieu NGROK_TOKEN trong .env, lay tai https://dashboard.ngrok.com/get-started/your-authtoken"; exit 1; }
	@grep -qF '$(NGROK_TOKEN)' $(NGROK_CFG) 2>/dev/null || $(NGROK) config add-authtoken $(NGROK_TOKEN)

# Mongo la tuy chon. Khong co docker, hoac MONGO_URI tro ra ngoai, thi bo qua
# va proxy van chay: capture tu dong quay ve ghi hex vao file log.
mongo-up:       ## dung container mongo neu can va neu may co docker
	@case "$(MONGO_URI)" in \
	  *127.0.0.1*|*localhost*) ;; \
	  "") echo "mongo: MONGO_URI trong .env dang de trong, bo qua container"; exit 0 ;; \
	  *)  echo "mongo: MONGO_URI tro ra ngoai, khong can container local"; exit 0 ;; \
	esac; \
	command -v docker >/dev/null 2>&1 || { \
	  echo "mongo: may nay khong co docker, bo qua."; \
	  echo "       proxy van chay, log ghi vao file, doc bang: ./dumpread $(if $(LOG_FILE),$(LOG_FILE),proxy.log)"; \
	  exit 0; }; \
	docker inspect -f '{{.State.Running}}' $(MONGO_NAME) 2>/dev/null | grep -qx true || { \
	  docker start $(MONGO_NAME) >/dev/null 2>&1 || \
	  docker run -d --name $(MONGO_NAME) -p $(MONGO_PORT):27017 -v $(MONGO_NAME)-data:/data/db $(MONGO_IMG) >/dev/null; }; \
	n=0; until docker exec $(MONGO_NAME) mongosh --quiet --eval 'db.runCommand({ping:1})' >/dev/null 2>&1; do \
	  n=$$((n+1)); test $$n -lt 60 || { echo "mongo khong len sau 60s, xem: docker logs $(MONGO_NAME)"; exit 1; }; sleep 1; done; \
	echo "mongo: $(MONGO_NAME) san sang tren cong $(MONGO_PORT)"

mongo-shell:    ## mo shell mongo de tu truy van
	docker exec -it $(MONGO_NAME) mongosh

mongo-down:     ## dung container mongo (du lieu van con trong volume)
	-docker stop $(MONGO_NAME)

bore-local:     ## tai bore ve thu muc nay neu chua co (khong can the, khong can tai khoan)
	@test -x ./bore || { echo "tai bore..."; curl -sL $(BORE_URL) | tar xz bore && echo "xong: $$(./bore --version)"; }

env:            ## tao .env tu .env.example va bat buoc doi mat khau proxy
	@test -f .env || { cp .env.example .env; echo "da tao .env tu .env.example"; }
	@grep -qE '^PROXY_AUTH=.+:.+' .env || { \
	  echo "thieu PROXY_AUTH trong .env. Them dong: PROXY_AUTH=ten:matkhau"; exit 1; }
	@grep -qE '^PROXY_AUTH=user:pass$$' .env && { \
	  echo "PROXY_AUTH trong .env van la mac dinh user:pass."; \
	  echo "Doi thanh mat khau rieng truoc khi mo proxy ra internet."; exit 1; } || true

up: env build dumpread mongo-up bore-local  ## MOT LENH: mongo + proxy + bore.pub (khong can the), Ctrl+C tat het
	@./$(BIN) & PID=$$!; \
	  trap "kill -INT $$PID 2>/dev/null" EXIT; \
	  trap "kill -INT $$PID 2>/dev/null; exit 0" INT TERM; \
	  sleep 1; echo "=> dia chi co dinh: http://<user>:<pass>@bore.pub:$(BORE_PORT)"; echo "=> doc log: ./dumpread"; \
	  $(BORE) local $(HTTP_PORT) --to bore.pub --port $(BORE_PORT)

up-ngrok: env build dumpread mongo-up ngrok-local ngrok-setup  ## nhu up nhung qua ngrok (CAN khai the ngrok)
	@./$(BIN) & PID=$$!; \
	  trap "kill -INT $$PID 2>/dev/null" EXIT; \
	  trap "kill -INT $$PID 2>/dev/null; exit 0" INT TERM; \
	  sleep 1; $(NGROK) tcp $(HTTP_PORT)

tunnel:         ## chi mo bore (proxy phai dang chay san)
	$(BORE) local $(HTTP_PORT) --to bore.pub --port $(BORE_PORT)

logs:           ## xem log tren VPS
	ssh $(VPS) journalctl -u proxy -f

clean:
	rm -f $(BIN) dumpread

help:
	@grep -hE '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'

.PHONY: env run-proxy build dumpread test mongo-up mongo-shell mongo-down deploy bore-local ngrok-local ngrok-setup tunnel up up-ngrok logs clean help
