require 'fastlane_core/ui/ui'
require 'digest'
require 'json'

module Fastlane
  UI = FastlaneCore::UI unless Fastlane.const_defined?("UI")

  module Helper
    class RustoreHelper
      def self.connection
        require 'faraday'
        require 'faraday_middleware'

        open_to = Integer(ENV.fetch("RUSTORE_OPEN_TIMEOUT", 30).to_s)
        read_to = Integer(ENV.fetch("RUSTORE_READ_TIMEOUT", 180).to_s)
        write_to = Integer(ENV.fetch("RUSTORE_WRITE_TIMEOUT", 180).to_s)
        
        options = {
          url: "https://public-api.rustore.ru",
          request: {
            open_timeout: open_to, # время на установку TCP
            timeout:      read_to, # общий (часто = read)
            read_timeout: read_to, # явный read (Faraday v2 / Net::HTTP поддерживает)
            write_timeout: write_to
          }
        }

        logger = Logger.new($stderr)
        logger.level = Logger::DEBUG

        Faraday.new(options) do |builder|
          builder.request(:multipart)
          builder.request(:json)
          builder.request(:url_encoded)
          builder.response(:json, content_type: /\bjson$/)
          builder.response(:logger, logger)
          builder.use(FaradayMiddleware::FollowRedirects)
          builder.adapter(:net_http)
        end
      end

      def self.rsa_sign(timestamp, key_id, private_key)
        key = OpenSSL::PKey::RSA.new("-----BEGIN RSA PRIVATE KEY-----\n#{private_key}\n-----END RSA PRIVATE KEY-----")
        signature = key.sign(OpenSSL::Digest.new('SHA512'), key_id + timestamp)
        Base64.encode64(signature)
      end

      def self.get_token(key_id:, private_key:)
        timestamp = DateTime.now.iso8601(3)
        signature = rsa_sign(timestamp, key_id, private_key)
        url = "/public/auth/"
        response = connection.post(url) do |req|
          req.body = { keyId: key_id, timestamp: timestamp, signature: signature }
        end

        UI.message("Debug: response #{response.body}")

        response.body["body"]["jwe"]
      end

      def self.create_draft(token, package_name, publish_type)
        url = "/public/v1/application/#{package_name}/version"
        response = connection.post(url) do |req|
          req.headers['Public-Token'] = token
          req.body = {}
          req.body['publishType'] = publish_type unless publish_type.nil?
        end

        UI.message("Debug: response #{response.body}")
        if response.body["body"]
          # Если черновика не было, и мы создали новый, здесь будет draftId
          return response.body["body"]
        elsif response.body["message"]
          # Если черновик уже существовал, в message будет ошибка вида
          # "You already have draft version with ID = XXXXXXXXXX", откуда достаем ID существующего черновика.
          return response.body["message"].scan(/\d+/).first.to_i
        else
          raise "Couldn't get draftId from RuStore"
        end
      end

      def self.upload_apk(token, draft_id, is_hms, file_path, package_name)
        if is_hms
          apk_type = "HMS"
          is_main = false
        else
          apk_type = "Unknown"
          is_main = true
        end

        url = "/public/v1/application/#{package_name}/version/#{draft_id}/apk"
        payload = {}
        payload[:file] = Faraday::Multipart::FilePart.new(file_path, 'application/vnd.android.package-archive')

        response = connection.post(url) do |req|
          req.headers['Public-Token'] = token
          req.params['servicesType'] = apk_type
          req.params['isMainApk'] = is_main
          req.body = payload
        end

        if response.body["message"] == "File was not uploaded successfully: The code of this version must be larger than that of the previous one"
          raise "Build with this version code was already uploaded earlier"
        end

        UI.message("Debug: response #{response.body}")
      end

      def self.upload_aab(token, draft_id, file_path, package_name)
        url = "/public/v1/application/#{package_name}/version/#{draft_id}/aab"
        payload = {}
        payload[:file] = Faraday::Multipart::FilePart.new(file_path, 'application/octet-stream')

        response = connection.post(url) do |req|
          req.headers['Public-Token'] = token
          req.body = payload
        end

        if response.body["message"] == "File was not uploaded successfully: The code of this version must be larger than that of the previous one"
          raise "Build with this version code was already uploaded earlier"
        end

        UI.message("Debug: response #{response.body}")
      end

      def self.commit_version(token, draft_id, package_name)
        url = "/public/v1/application/#{package_name}/version/#{draft_id}/commit"
        response = connection.post(url) do |req|
          req.headers['Public-Token'] = token
        end

        UI.message("Debug: response #{response.body}")
      end
    end
  end
end
