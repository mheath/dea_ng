require("dea/firewall/firewall")

module Dea
  module Firewall

    class RouterRegistry
      ROUTER_TIMEOUT = 300 # 5 minutes

      def initialize(firewall = Dea::Firewall::Firewall.new)
        @routers = {}
        @firewall = firewall
      end

      def update(host)
        modified = false
        router = @routers[host]
        if router == nil
          router = Router.new(host)
          @routers[host] = router
          logger.info("Adding router #{host} to incoming firewall rules")
          modified = true
        end
        router.update
        @routers.delete_if do |host, router|
          remove = Time.now - router.last_updated > ROUTER_TIMEOUT
          if remove
            logger.info("Removing router #{host} from incoming firewall rules")
            modified = true
          end
          remove
        end
        if modified
          @firewall.update(@routers.keys)
        end
      end

    end

    class Router
      attr_reader :host
      attr_reader :last_updated

      def initialize(host)
        @host = host
        update
      end

      def update
        @last_updated = Time.now
      end
    end

  end
end