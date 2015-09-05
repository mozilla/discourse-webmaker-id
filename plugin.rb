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

after_initialize do
  class ::OmniAuth::Strategies::Webmaker
    option :client_options, {
      :site => SiteSetting.webmaker_server,
      :authorize_url => '/login/oauth/authorize',
      :token_url => '/login/oauth/access_token'
    }
  end
end

class OmniAuth::Strategies::Webmaker < OmniAuth::Strategies::OAuth2
  option :name, 'webmaker'

  option :authorize_params, {
    :response_type => 'code',
    :scopes => 'user email'
  }

  def request_phase
    redirect client.auth_code.authorize_url(authorize_params)
  end

  def build_access_token
    verifier = request.params["code"]
    client.auth_code.get_token(verifier, {}, {:header_format => 'token %s'})
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
    @raw_info ||= access_token.get('/user').parsed
  end
end

auth_provider :title => 'with Webmaker',
  :message => 'Authentication with Webmaker (make sure pop up blockers are not enabled)',
  :frame_width => 660,
  :frame_height => 650,
  :authenticator => WebmakerAuthenticator.new('webmaker', trusted: true)

register_css <<CSS

.btn-social.webmaker {
  background: #C13832;
}

CSS
