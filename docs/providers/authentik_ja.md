# Authentik OIDC プロバイダー設定ガイド

このドキュメントでは、Supabase AuthでAuthentikをOIDC（OpenID Connect）プロバイダーとして使用する方法について説明します。

## 概要

Authentikは、OIDC、SAML、その他の認証プロトコルをサポートするオープンソースのアイデンティティプロバイダーです。この統合により、ユーザーはAuthentikの認証情報を使用してSupabaseにログインできるようになります。

## 前提条件

- 稼働中のAuthentikインスタンス
- Authentikの管理者アクセス権限
- Supabase Authインスタンス（セルフホストまたはクラウド）

## Authentik側の設定

### 1. OAuth2/OpenIDプロバイダーの作成

1. Authentik管理画面にログイン
2. **Applications** → **Providers** に移動
3. **Create** をクリックし、**OAuth2/OpenID Provider** を選択
4. 以下の設定でプロバイダーを構成：
   - **Name**: わかりやすい名前（例：「Supabase Auth」）
   - **Authorization flow**: 希望するフロー（implicitまたはauthorization code）を選択
   - **Client type**: Confidential
   - **Client ID**: 自動生成またはカスタム（この値を保存）
   - **Client Secret**: 自動生成（この値を保存）
   - **Redirect URIs**: `https://your-supabase-domain/auth/v1/callback`

### 2. アプリケーションの作成

1. **Applications** → **Applications** に移動
2. **Create** をクリック
3. アプリケーションを設定：
   - **Name**: わかりやすい名前（例：「Supabase」）
   - **Slug**: OAuth URLの一部になります（例：「supabase」）
   - **Provider**: ステップ1で作成したプロバイダーを選択
   - **UI settings**: 必要に応じて設定

### 3. OAuthエンドポイントの確認

アプリケーション作成後、以下のURLを確認：
- **Authorization URL**: `https://your-authentik-domain/application/o/authorize/`
- **Token URL**: `https://your-authentik-domain/application/o/token/`
- **User Info URL**: `https://your-authentik-domain/application/o/userinfo/`
- **Application URL**: `https://your-authentik-domain/application/o/{slug}/`

## Supabase Auth側の設定

### 環境変数

Supabase Authの設定に以下の環境変数を追加：

```bash
# Authentikプロバイダーを有効化
GOTRUE_EXTERNAL_AUTHENTIK_ENABLED=true

# Authentik OAuth認証情報
GOTRUE_EXTERNAL_AUTHENTIK_CLIENT_ID=your_client_id
GOTRUE_EXTERNAL_AUTHENTIK_SECRET=your_client_secret

# リダイレクトURI（Authentik設定と一致させる）
GOTRUE_EXTERNAL_AUTHENTIK_REDIRECT_URI=https://your-supabase-domain/auth/v1/callback

# AuthentikアプリケーションURL
# 形式: https://your-authentik-domain/application/o/{slug}
GOTRUE_EXTERNAL_AUTHENTIK_URL=https://your-authentik-domain/application/o/supabase
```

### Docker Compose設定（セルフホスト）

Docker Composeを使用する場合、authサービスに環境変数を追加：

```yaml
services:
  auth:
    environment:
      GOTRUE_EXTERNAL_AUTHENTIK_ENABLED: ${GOTRUE_EXTERNAL_AUTHENTIK_ENABLED}
      GOTRUE_EXTERNAL_AUTHENTIK_CLIENT_ID: ${GOTRUE_EXTERNAL_AUTHENTIK_CLIENT_ID}
      GOTRUE_EXTERNAL_AUTHENTIK_SECRET: ${GOTRUE_EXTERNAL_AUTHENTIK_SECRET}
      GOTRUE_EXTERNAL_AUTHENTIK_REDIRECT_URI: ${GOTRUE_EXTERNAL_AUTHENTIK_REDIRECT_URI}
      GOTRUE_EXTERNAL_AUTHENTIK_URL: ${GOTRUE_EXTERNAL_AUTHENTIK_URL}
```

### マルチドメイン環境の設定

Supabase Authが異なるサブドメインで実行される場合：

```bash
# Cookieドメイン設定（サブドメイン間でCookieを共有）
GOTRUE_COOKIE_DOMAIN=.example.com
GOTRUE_COOKIE_NAME=sb-auth-token
GOTRUE_COOKIE_SECURE=true
GOTRUE_COOKIE_SAMESITE=lax
```

## 使用方法

### 認証の開始

ユーザーをAuthentikで認証するには、以下のURLにリダイレクト：

```
https://your-supabase-domain/auth/v1/authorize?provider=authentik
```

### JavaScriptクライアントの例

Supabase JavaScriptクライアントを使用：

```javascript
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY)

// Authentikでサインイン
const { data, error } = await supabase.auth.signInWithOAuth({
  provider: 'authentik',
  options: {
    redirectTo: 'https://your-app.com/auth/callback'
  }
})
```

## ユーザーデータマッピング

Authentikプロバイダーは以下のデータをマッピングします：

| Authentikクレーム | Supabaseユーザーフィールド |
|-----------------|------------------------|
| `sub` | `id`（identity内） |
| `email` | `email` |
| `email_verified` | `email_confirmed_at` |
| `name` | `user_metadata.full_name` |
| `given_name` | `user_metadata.first_name` |
| `family_name` | `user_metadata.last_name` |
| `nickname` | `user_metadata.username` |
| `preferred_username` | `user_metadata.preferred_username` |
| `picture` | `user_metadata.avatar_url` |
| `phone_number` | `user_metadata.phone` |

Authentikからの追加クレームは`user_metadata`に保存されます。

## トラブルシューティング

### よくある問題

1. **「Redirect URI Error」**
   - AuthentikのリダイレクトURIが`GOTRUE_EXTERNAL_AUTHENTIK_REDIRECT_URI`と完全に一致することを確認
   - 完全なパス（`/auth/v1/callback`）を含めることを確認

2. **「flow_state_not_found」エラー**
   - PKCEフローが中断された場合に発生
   - ブラウザでCookieが有効になっていることを確認
   - サブドメイン間でCookieを共有する場合は、Cookie設定を確認

3. **ユーザーデータの欠落**
   - 要求されたスコープがAuthentikで設定されていることを確認
   - Authentikでユーザーに必要な属性が設定されていることを確認

### デバッグモード

トラブルシューティングのためにデバッグログを有効化：

```bash
GOTRUE_LOG_LEVEL=debug
```

## セキュリティに関する考慮事項

1. **本番環境では必ずHTTPSを使用**
2. **クライアントシークレットを安全に保管** - クライアントサイドのコードに公開しない
3. **適切なリダイレクトURIを設定** - リダイレクト攻撃を防ぐ
4. **定期的にクライアントシークレットをローテーション**

## 高度な設定

### カスタムクレーム

Authentikでは、IDトークンにカスタムクレームを追加できます。これらはSupabaseの`user_metadata`で利用可能になります。

### グループマッピング

Authentikのグループ情報をSupabaseのロールにマッピングする場合：
1. Authentikでクレームにグループ情報を含めるよう設定
2. Supabase Auth Hooksを使用してクレームを処理し、適切なロールを割り当て

### 多要素認証（MFA）

AuthentikでMFAが有効な場合、認証フロー中に追加の認証ステップが必要になります。

## 参考資料

- [Authentik公式ドキュメント](https://goauthentik.io/docs/)
- [Supabase Auth公式ドキュメント](https://supabase.com/docs/guides/auth)
- [OpenID Connect仕様](https://openid.net/connect/)