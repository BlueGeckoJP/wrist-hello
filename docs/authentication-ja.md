# 認証プロセスの仕様

## 認証の軸・何を持って認証済みとするか

主な判別内容は以下

- 時計が近くにあるか
  これはBLEで通信できるかで判別する 将来的にどれぐらい離れているかの条件をつけても良い
- 時計がペアリングされているか
  ペアリングを前提にする これが承認しているデバイスかどうかを判断する一つの要素
- 時計がchallenge characteristicを正しく署名できるか
  認証のメイン要素 秘密鍵/公開鍵のペアで持つ この2つは時計側で生成・配布する
- 時計が通知を通してユーザーからサインインの承諾をもらえるか

## Wrist認証成功の条件

以下のすべてを満たした場合にWrist認証成功とする

- pam-moduleとlinux-daemonが通信できる
- linux-daemonに接続してきたpam-moduleのUNIX Socketのpeer credentialがrootである
- 対象の時計とBLE接続ができる
- 時計の通知を通してユーザーがサインインを承諾する
- 時計がPCから送られたchallengeに対して正しい秘密鍵で署名できる
- linux-daemonが設定済み公開鍵で署名を正しく検証できる

ここでいう成功はWrist認証単体の成功を指す。
PAMスタック全体の認証結果はPAM設定に従う。

## 後続のPAM認証へのフォールバック

pam-moduleはWrist認証を開始した後、ユーザーがEnterを押した場合に`PAM_IGNORE`を返し、後続のPAMモジュールへ処理を委ねる。

Enterが押された場合、pam-moduleは進行中のWrist認証待ちをキャンセルして即座にフォールバックする。

Wrist認証が失敗・拒否・タイムアウトした場合や、Wrist認証処理を開始できない場合は`PAM_AUTH_ERR`を返す。

Wrist認証が成功した場合は`PAM_SUCCESS`を返す。PAMスタック全体での扱いはPAM設定に従う。

## 認証キャッシュの扱い

linux-daemonではWrist認証成功後、短時間だけ認証済みの状態を保持する

この期間中にpam-moduleから認証要求が来たとき、BLE challenge/responseをバイパスし成功として返す

この状態は永続的なものではない linux-daemonのメモリ上のみで保持し、linux-daemonの再起動で失われる

認証キャッシュの有効秒数は変更でき、0にすれば毎回キャッシュを使用せず認証プロセスを起動できる

## linux-daemon <-> wearos-app間のchallenge responseについて

wearos-app側でユーザーからサインインの承認がおりた場合は署名済みのチャレンジレスポンスが送信される

もしサインインの承認がおりなかった場合・wearos-app側のユーザーへの承認がタイムアウトした場合は`0x00`に現在のchallengeを続けたdeny responseが送信される(`0x00` + challenge)

## 各コンポーネントの役割

### pam-module

- ユーザーからの認証を受け取る役割
- Wrist認証プロセスはUNIX Socket経由でlinux-daemonに依頼する
- 認証情報(uid, tty, service)をlinux-daemonに送信
- UNIX Socket経由でlinux-daemonの成功/失敗の結果を受け取りPAMに返す
- Wrist認証中にEnterが押された場合はWrist認証待ちをキャンセルし、後続のPAMモジュールへフォールバックする
- Wrist認証が失敗・拒否・タイムアウトした場合や、Wrist認証処理を開始できない場合は`PAM_AUTH_ERR`を返す

### linux-daemon

- UNIX Socket経由でpam-moduleから認証の開始を受けとり結果を返す
- PC側の認証プロセスはここで行われる
- challenge/response characteristicsを提供する
- pam-moduleから認証開始を受け取ったら新しいchallenge characteristicを設定しwearos-appに通知する
- wearos-appから受け取ったデータが成功(署名済みデータ)か失敗(`0x00` + challenge のdeny response)かを判断する
- wearos-appから受け取った署名を公開鍵で署名を検証する
- Wrist認証成功後pam-moduleに結果を送信
- Wrist認証成功後一定期間は通常の認証プロセスをバイパスし、即認証済みとしてpam-moduleに送信する (キャッシュ機能 キャッシュの秒数は変更可)

### wearos-app

- BLE経由でchallenge characteristicを受け取る
- 通知を通してユーザーにサインインの承諾を得る
- サインインの承諾が得られない場合、即時`0x00` + challenge のdeny responseをlinux-daemonに返す
- サインインの承諾が得られた場合、Android Keystoreに保持してある秘密鍵でchallengeに署名する
- サインインの承諾が得られた場合、署名をresponse characteristicに書き込む
