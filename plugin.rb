# name: webmaker-id
# about: Plugin which adds Webmaker authentication
# version: 0.0.1
# authors: Leo McArdle

require 'auth/oauth2_authenticator'
require 'omniauth-oauth2'

class WebmakerAuthenticator < ::Auth::OAuth2Authenticator
  def register_middleware(omniauth)
    omniauth.provider :webmaker,
    SiteSetting.webmaker_client_id,
    SiteSetting.webmaker_client_secret
  end
end

class OmniAuth::Strategies::Webmaker < OmniAuth::Strategies::OAuth2
  option :name, 'webmaker'

  option :client_options, {
    :site => 'https://id.webmaker.org',
    :authorize_url => 'https://id.webmaker.org/login/oauth/authorize',
    :token_url => 'https://id.webmaker.org/login/oauth/access_token'
  }

  option :authorize_params, {
    :response_type => 'code',
    :scopes => 'user'
  }

  def request_phase
    redirect client.auth_code.authorize_url(authorize_params)
  end

  uid { raw_info['id'].to_s }

  info do
    {
      :email => raw_info['email'],
      :name => raw_info['username']
    }
  end

  extra do
    {
      :raw_info => raw_info
    }
  end

  def raw_info
    @raw_info ||= access_token.get('user').parsed
  end
end

auth_provider :title => 'with Webmaker',
  :message => 'Authentication with Webmaker (make sure pop up blockers are not enabled)',
  :frame_width => 920,
  :frame_height => 800,
  :authenticator => WebmakerAuthenticator.new('webmaker', trusted: true)

register_css <<CSS

.btn-social.webmaker {
  background: #C13832;
}

CSS
