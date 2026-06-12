default:
  @just --list

build-daemon-release:
  cd linux-daemon && cargo build --release

build-linux:
  cd common && make all
  cd pam-module && make all
  cd linux-daemon && cargo build

build: build-linux
  cd wearos-app && ./gradlew assembleDebug

test: build
  cd wearos-app && ./gradlew test

clean:
  cd common && make clean
  cd pam-module && make clean
  cd linux-daemon && cargo clean
  cd wearos-app && ./gradlew clean

fmt:
  cd common && clang-format -i *.c *.h
  cd pam-module && clang-format -i *.c
  cd linux-daemon && cargo fmt

gen-compile-commands:
  cd common && make clean && bear -- make all
  cd pam-module && make clean && bear -- make all

lint: gen-compile-commands
  cd common && clang-tidy *.c
  cd pam-module && clang-tidy *.c
  cd linux-daemon && cargo clippy
  cd wearos-app && ./gradlew lint

install: build-linux build-daemon-release
  sudo mkdir -p /usr/local/sbin/wrist-hello
  sudo mkdir -p /etc/wrist-hello
  sudo cp linux-daemon/target/release/linux-daemon /usr/local/sbin/wrist-hello/daemon
  sudo cp pam-module/pam-module.so /lib/security/pam_wrist_hello.so
  sudo cp wrist-hello.service /etc/systemd/system/wrist-hello.service
  sudo systemctl daemon-reload

uninstall:
  sudo systemctl disable --now wrist-hello.service || true
  sudo rm -f /etc/systemd/system/wrist-hello.service
  sudo rm -f /lib/security/pam_wrist_hello.so
  sudo rm -rf /usr/local/sbin/wrist-hello
  sudo systemctl daemon-reload

clean-uninstall: uninstall
  sudo rm -rf /etc/wrist-hello
