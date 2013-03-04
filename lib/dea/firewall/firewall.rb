# coding: UTF-8

require "dea/firewall/iptables"

module Dea
  module Firewall
    class Firewall
      DISPATCH_CHAIN = "warden-dispatch"
      FIREWALL_CHAIN = "firewall-in"

      def initialize(iptables = Dea::Firewall::IpTables::new)
        @iptables = iptables
      end

      def update(hosts)
        # Make sure Warden's default ACCEPT rules have been removed from Warden's dispatch chain
        remove_dispatch_accept_rules
        # Make sure the Firewall's chain has been created and inserted into Warden's dispatch chain
        check_firewall_chain

        existing_rules = @iptables.list_rules(@firewall_chain)

        # Append new rules
        hosts.each_value do |host|
          @iptables.append_rule(@firewall_chain, "-d #{host} -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT")
        end

        # Remove old rules
        existing_rules.each { @iptables.delete_rule(@firewall_chain, 1) }
      end

      def remove_dispatch_accept_rules
        rule_num = nil
        begin
          dispatch_rules = @iptables.list_rules(@dispatch_chain)
          raise "Dispatch chain #{@dispatch_chain} does not exist" unless dispatch_rules.length != 0
          rule_num = dispatch_rules.index do |rule|
            rule.include? 'ACCEPT'
          end
          if rule_num != nil
            logger.info("Removing rule '#{dispatch_rules[rule_num]}'")
            @iptables.remove_rule(@dispatch_chain, rule_num)
          end
        end until rule_num == nil
      end

      def check_firewall_chain
        firewall_chain_rules = @iptables.list_rules(@firewall_chain)
        if firewall_chain_rules.length == 0
          logger.debug('Creating firewall chain')
          @iptables.create_chain(@firewall_chain)
        end
        firewall_jump_rule = @iptables.list_rules(@dispatch_chain).index do |rule|
          rule.include? "-g #{@firewall_chain}"
        end
        if firewall_jump_rule == nil
          logger.debug('Inserting firewall chain into Warden dispatch chain')
          @iptables.insert_rule(@dispatch_chain, "-g #{@firewall_chain}")
        end
      end
    end
  end
end