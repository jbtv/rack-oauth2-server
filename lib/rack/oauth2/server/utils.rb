module Rack
  module OAuth2
    class Server

      module Utils
        module_function

        # Parses the redirect URL, normalizes it and returns a URI object.
        #
        # Raises InvalidRequestError if not an absolute HTTP/S URL.
        def parse_redirect_uri(redirect_uri)
          raise InvalidRequestError, "Missing redirect URL" unless redirect_uri
          uri = URI.parse(redirect_uri).normalize rescue nil
          raise InvalidRequestError, "Redirect URL looks fishy to me" unless uri
          raise InvalidRequestError, "Redirect URL must be absolute URL" unless uri.absolute? && uri.host
          uri
        end
        
        def parse_verification_uri(verification_uri)
          raise InvalidRequestError, "Missing device verification URL" unless verification_uri
          uri = URI.parse(verification_uri).normalize rescue nil
          raise InvalidRequestError, "Redirect URL looks fishy to me" unless uri
          raise InvalidRequestError, "Redirect URL must be absolute URL" unless uri.absolute? && uri.host
          uri
        end

        # Given scope as either array or string, return array of same names,
        # unique and sorted.
        def normalize_scope(scope)
          (Array === scope ? scope.join(" ") : scope || "").split(/\s+/).compact.uniq.sort
        end

      end

    end
  end
end
