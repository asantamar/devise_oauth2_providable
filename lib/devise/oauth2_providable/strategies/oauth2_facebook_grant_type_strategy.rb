require 'devise/oauth2_providable/strategies/oauth2_grant_type_strategy'

module Devise
  module Strategies
    class Oauth2FacebookGrantTypeStrategy < Oauth2GrantTypeStrategy
      def grant_type
        'facebook'
      end

      def authenticate_grant_type(client)
        resource = mapping.to.find_for_authentication(:uid => params[:uid], :provider => 'facebook')
        if validate(resource) { params[:token] == resource.fb_token }
          success! resource
        else
          oauth_error! :invalid_grant, 'invalid facebook authentication request'
        end
      end
    end
  end
end

Warden::Strategies.add(:oauth2_facebook_grantable, Devise::Strategies::Oauth2FacebookGrantTypeStrategy)

