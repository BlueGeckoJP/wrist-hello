# 認証プロセスの仕様

## 認証の軸・何を持って認証済みとするか

主な判別内容は以下

- 時計が近くにあるか
  これはBLEで通信できるかで判別する 将来的にどれぐらい離れているかの条件をつけても良い
- 時計がペアリングされているか
  ペアリングを前提にする これが承認しているデバイスかどうかを判断する一つの要素
- 時計がchallenge characteristicを正しく署名できるか
  認証のメイン要素 秘密鍵/公開鍵のペアで持つ この2つは時計側で生成・配布する

## 認証成功の条件

以下のすべてを満たした場合に認証成功とする

- pam-moduleとlinux-daemonが通信できる
- linux-daemonに接続してきたpam-moduleのUNIX Socketのpeer credentialがrootである
- 対象の時計とBLE接続ができる
- 時計がPCから送られたchallengeに対して正しい秘密鍵で署名できる
- linux-daemonが設定済み公開鍵で署名を正しく検証できる

## 認証キャッシュの扱い

linux-daemonでは認証成功後、短時間だけ認証済みの状態を保持する

この期間中にpam-moduleから認証要求が来たとき、BLE challenge/responseをバイパスし成功として返す

この状態は永続的なものではない linux-daemonのメモリ上のみで保持し、linux-daemonの再起動で失われる

## 各コンポーネントの役割

### pam-module

- ユーザーからの認証を受け取る役割
- 認証プロセスはUNIX Socket経由でlinux-daemonに丸投げする
- 認証情報(uid, tty, service)をlinux-daemonに送信
- UNIX Socket経由でlinux-daemonの成功/失敗の結果を受け取りPAMに返す

### linux-daemon

- UNIX Socket経由でpam-moduleから認証の開始を受けとり結果を返す
- PC側の認証プロセスはここで行われる
- challenge/response characteristicsを提供する
- pam-moduleから認証開始を受け取ったら新しいchallenge characteristicを設定しwearos-appに通知する
- wearos-appから受け取った署名を公開鍵で署名を検証する
- 認証成功後pam-moduleに結果を送信
- 認証成功後一定期間は通常の認証プロセスをバイパスし、即認証済みとしてpam-moduleに送信する (キャッシュ機能)

### wearos-app

- BLE経由でchallenge characteristicを受け取る
- Android Keystoreに保持してある秘密鍵でchallengeに署名する
- 署名をresponse characteristicに書き込む
