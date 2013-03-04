# coding: UTF-8

module Dea
  module Firewall
    class IpTables

      def list_rules(chain)
        out = `iptables -S #{chain}`
        logger.error("No iptables chain with name #{chain}") unless $? == 0
        out.split("\n")
      end

      def remove_rule(chain, rulenum)
        `iptables -D #{chain} #{rulenum}`
        raise "Error removing rule from chain #{chain}" unless $? == 0
      end

      def insert_rule(chain, rule, rulenum = 1)
        `iptables -I #{chain} #{rulenum} #{rule}`
        raise "Error inserting rule '#{rule}' into chain #{chain}" unless $? == 0
      end

      def append_rule(chain, rule)
        `iptables -A #{chain} #{rule}`
        raise "Error inserting rule '#{rule}' into chain #{chain}" unless $? == 0
      end

      def create_chain(chain)
        `iptables -N #{chain}`
        raise "Error creating chain #{chain}" unless $? == 0
      end

      def delete_chain(chain)
        `iptables -X #{chain}`
        raise "Error deleting chain #{chain}" unless $? == 0
      end

    end
  end
end