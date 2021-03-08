require 'colorize'
test_name "Puppet facts diff should show inconsistency between facter 3 and facter 4 outputs"

tag 'audit:high',
    'audit:integration'

$modules_path = nil
$core_diffs = nil

$puppet_commit = nil
$facter3_version = nil
$facter_ng_commit = nil

def print_diff(host, tag, version = nil)
  on(host, puppet('facts', 'diff'), :accept_all_exit_codes => true) do |result|
    output = result.stdout.chomp
    begin
      unless output.empty?
        parsed = JSON.parse(output)
        if tag == "core_facts_filtered"
          $core_diffs = parsed
        else
          unless tag == "core_facts_unfiltered" || tag == "core_facts_with_new_filters"
            puts "Found keys:"
            parsed.each do |key, value|
              puts "'#{key}'"
            end
            $core_diffs.each do |key, value|
              puts "Attempting to delete '#{key}'"
              parsed.delete(key)
            end
          end
        end
        unless parsed.empty?
          puts JSON.pretty_generate(parsed)
          puts ">> Parseable version:"
          parseable = JSON.pretty_generate(parsed).gsub("\n","")
          puts "<<--#{tag}@#{version}-->>#{parseable}<</--#{tag}@#{version}--/>>"
        else
          puts "<<--#{tag}@#{version}-->>{ \"NO DIFFS\": \"All good here!\" }<</--#{tag}@#{version}--/>>"
        end
      end
    rescue
      reasons = output.scan(/fact (fact=.+)\n/).flatten.map(&:chomp)
      reasons.uniq!
      puts "<<--#{tag}@#{version}-->>{ \"Not working due\": [ \"#{reasons.join("\", \"")}\" ] }<</--#{tag}@#{version}--/>>"
    end
  end
end

def print_diff_module(host, module_name, version = nil)
  host.rm_rf("'#{$modules_path}/'*")
  
  unless module_name.include?('https://')
    full = ''
    loop do
      unless version.nil?
        on(host, puppet('module', 'install', module_name, '--version', version), :accept_all_exit_codes => true) do |result|
          full = result.stdout + result.stderr
        end
      else
        on(host, puppet('module', 'install', module_name), :accept_all_exit_codes => true) do |result|
          full = result.stdout + result.stderr
          version = result.stdout.chomp.match(/#{module_name.gsub('/','-')} \((.+)\)/)[1] unless full.include?('504 Gateway Time-out')
        end
      end
      break unless full.include?('504 Gateway Time-out')
    end
  else
    folder = nil
    on(host, "cd '#{$modules_path}' && git clone #{module_name}") do |result|
      folder = result.stdout.chomp.match(/Cloning into \'(.+)\'\.\.\./)
      unless folder.nil?
        folder = folder[1]
      else
        folder = result.stderr.chomp.match(/Cloning into \'(.+)\'\.\.\./)
        if folder.nil?
          folder = on(host, "ls '#{$modules_path}'").stdout.chomp
        else
          folder = folder[1]
        end
      end
    end
    unless version.nil?
      on(host, "cd '#{$modules_path}/#{folder}' && git fetch --all && git checkout #{version}")
    else
      commit = on(host, "cd '#{$modules_path}/#{folder}' && git rev-parse --short HEAD").stdout.chomp
      version = on(host, "cd '#{$modules_path}/#{folder}' && git rev-parse --abbrev-ref HEAD").stdout.chomp + "(commit:#{commit})"
    end
  end

  module_name = module_name.gsub('/','-').split('-').last(2).join('-').gsub('.git','').chomp
  print_diff(host, module_name.gsub('/','-'), version.uncolorize)
end

agents.each do |agent|
  step 'prepare environment' do
    if agent['platform'] =~ /aix/
      on(agent, 'curl -O https://artifactory.delivery.puppetlabs.net/artifactory/generic__buildsources/openssl-1.0.2.1800.tar.Z; uncompress openssl-1.0.2.1800.tar.Z; tar xvf openssl-1.0.2.1800.tar; cd openssl-1.0.2.1800 && /usr/sbin/installp -acgwXY -d $PWD openssl.base; curl -O http://ftp.software.ibm.com/aix/freeSoftware/aixtoolbox/ezinstall/ppc/yum.sh && sh yum.sh; yum install -y git; yum update curl -y; yum install -y git')
    elsif agent['platform'] =~ /el-6/
      info = on(agent, 'cat /etc/centos-release').stdout.chomp
      puts info
      puts "DEBUG: PUTTING REPO"
      on(agent, 'curl https://www.getpagespeed.com/files/centos6-eol.repo --output /etc/yum.repos.d/CentOS-Base.repo') if info.include?('release 6')
    end

    on(agent, puppet('config', 'set', 'facterng', 'false'))
    
    on(agent, puppet('resource', 'package', "'git'", 'ensure=present')) unless agent['platform'] =~ /windows/

    puppet_lib_path = ''
    if agent['platform'] =~ /windows/
      puppet_lib_path = "/cygdrive/c/Program Files/Puppet Labs/Puppet/puppet/lib/ruby/vendor_ruby"
    else
      puppet_lib_path = "/opt/puppetlabs/puppet/lib/ruby/vendor_ruby"
    end

    puppet_version = on(agent, puppet('--version')).stdout.chomp
    puts "PUPPET VERSION BEFORE: #{puppet_version}"

    on(agent, "git clone https://github.com/puppetlabs/puppet.git", :accept_all_exit_codes => true)
    $puppet_commit = on(agent, "cd puppet && git rev-parse --short HEAD").stdout.chomp
    on(agent, "cd puppet && git checkout 6.x && cp -r 'lib/puppet/.' '#{puppet_lib_path}/puppet/.'")

    puppet_version = on(agent, puppet('--version')).stdout.chomp
    puts "PUPPET VERSION AFTER: #{puppet_version}"

    facterng_path = ''
    facterng_version = '4.0.50'
    if agent['platform'] =~ /windows/
      gem_version = on(agent, "ls '/cygdrive/c/Program Files/Puppet Labs/Puppet/puppet/lib/ruby/gems'").stdout.chomp
      facterng_path = "/cygdrive/c/Program Files/Puppet Labs/Puppet/puppet/lib/ruby/gems/#{gem_version}/gems/facter-ng-#{facterng_version}"
    else
      facterng_path = on(agent, "find /opt | grep facter-ng-#{facterng_version}$").stdout.chomp
    end

    facterng_version = on(agent, puppet('facts', 'show', '--facterng', 'facterversion', '--value-only')).stdout.chomp
    if facterng_version == '4.0.50'
      puts "FACTER VERSION BEFORE: #{facterng_version}"

      agent.rm_rf("'#{facterng_path}/'*")
      on(agent, "cd '#{facterng_path}' && git clone https://github.com/puppetlabs/facter.git .")
      
      facterng_version = on(agent, puppet('facts', 'show', '--facterng', 'facterversion', '--value-only')).stdout.chomp
      puts "FACTER VERSION AFTER: #{facterng_version}"
    end
    $facter_ng_commit = on(agent, "cd '#{facterng_path}' && git rev-parse --short HEAD").stdout.chomp
    $facter3_version = on(agent, puppet('facts', 'show', 'facterversion', '--value-only')).stdout.chomp
  end

  step 'test core facts with filter' do
    print_diff(agent, "core_facts_filtered", "Puppet@6.x(commit:#{$puppet_commit}),Facter@main(commit:#{$facter_ng_commit}),cFacter@#{$facter3_version}")
  end

  # Get modules path
  on agent, puppet('module', 'install', 'puppetlabs-vcsrepo')
  on agent, puppet('module', 'uninstall', '--force', 'puppetlabs-vcsrepo') do |result|
    $modules_path = result.stdout.chomp.match(/from (.+)/)[1]
  end

  # when ADD_SUPPORTED_MODULES is true
  print_diff_module(agent, "puppetlabs-vcsrepo")
  print_diff_module(agent, "puppetlabs-apt")
  print_diff_module(agent, "puppetlabs-firewall")
  print_diff_module(agent, "puppetlabs-postgresql")
  print_diff_module(agent, "puppetlabs-ntp")
  print_diff_module(agent, "puppetlabs-mysql")
  print_diff_module(agent, "puppetlabs-java")
  print_diff_module(agent, "puppetlabs-java_ks")
  print_diff_module(agent, "puppetlabs-registry")
  print_diff_module(agent, "puppetlabs-pwshlib")
  print_diff_module(agent, "puppetlabs-powershell")
  print_diff_module(agent, "puppetlabs-tomcat")
  print_diff_module(agent, "puppetlabs-reboot")
  print_diff_module(agent, "puppetlabs-acl")
  print_diff_module(agent, "puppet-prometheus", "10.2.0")

  # when ADD_APPROVED_MODULES is true
  print_diff_module(agent, "maestrodev/wget")
  print_diff_module(agent, "stahnma/epel")
  print_diff_module(agent, "nanliu/staging")
  print_diff_module(agent, "stankevich/python")
  print_diff_module(agent, "garethr/erlang")
  print_diff_module(agent, "elasticsearch/elasticsearch")
  print_diff_module(agent, "garethr/docker")
  print_diff_module(agent, "saz/rsyslog")
  print_diff_module(agent, "rtyler/jenkins")
  print_diff_module(agent, "rodjek/logrotate")
  print_diff_module(agent, "sensu/sensu")
  print_diff_module(agent, "camptocamp/openssl")
  print_diff_module(agent, "openshift/openshift_origin")
  print_diff_module(agent, "herculesteam/augeasproviders_core")
  print_diff_module(agent, "mayflower/php")
  print_diff_module(agent, "razorsedge/vmwaretools")
  print_diff_module(agent, "arioch/keepalived")
  print_diff_module(agent, "fsalum/newrelic")
  print_diff_module(agent, "badgerious/windows_env")
  print_diff_module(agent, "wdijkerman/zabbix")
  print_diff_module(agent, "ghoneycutt/dnsclient")
  print_diff_module(agent, "herculesteam/augeasproviders_shellvar")
  print_diff_module(agent, "camptocamp/kmod")
  print_diff_module(agent, "herculesteam/augeasproviders_ssh")
  print_diff_module(agent, "trlinkin/nsswitch")
  print_diff_module(agent, "razorsedge/cloudera")
  print_diff_module(agent, "cyberious/pget")
  print_diff_module(agent, "opentable/windowsfeature")
  print_diff_module(agent, "danzilio/virtualbox")
  print_diff_module(agent, "KyleAnderson/consul")
  print_diff_module(agent, "herculesteam/augeasproviders_sysctl")
  print_diff_module(agent, "example42/network")
  print_diff_module(agent, "jhoblitt/ganglia")
  print_diff_module(agent, "golja/gnupg")
  print_diff_module(agent, "herculesteam/augeasproviders_postgresql")
  print_diff_module(agent, "ghoneycutt/pam")
  print_diff_module(agent, "herculesteam/augeasproviders_base")
  print_diff_module(agent, "herculesteam/augeasproviders_pam")
  print_diff_module(agent, "jhoblitt/selenium")
  print_diff_module(agent, "mkrakowitzer/jira")
  print_diff_module(agent, "stackforge/keystone")
  print_diff_module(agent, "herculesteam/augeasproviders_grub")
  print_diff_module(agent, "herculesteam/augeasproviders_nagios")
  print_diff_module(agent, "herculesteam/augeasproviders")
  print_diff_module(agent, "herculesteam/augeasproviders_apache")
  print_diff_module(agent, "herculesteam/augeasproviders_puppet")
  print_diff_module(agent, "herculesteam/augeasproviders_syslog")
  print_diff_module(agent, "herculesteam/augeasproviders_mounttab")
  print_diff_module(agent, "mukaibot/bamboo")
  print_diff_module(agent, "puppet/stash")
  print_diff_module(agent, "puppet/iis")

  # ALWAYS
  print_diff_module(agent, 'npwalker/pe_metric_curl_cron_jobs')
  print_diff_module(agent, 'petems/swap_file')
  print_diff_module(agent, 'fiddyspence/sysctl')
  print_diff_module(agent, 'ghoneycutt/hosts')
  print_diff_module(agent, 'dwerder/graphite', '5.16.1')
  print_diff_module(agent, 'dwerder/grafana', '1.2.0')

  # ALWAYS but from git
  print_diff_module(agent, 'https://github.com/puppetlabs/clamps.git')
  print_diff_module(agent, 'https://github.com/hunner/puppet-hiera.git', '1.2.0')
  print_diff_module(agent, 'https://github.com/camptocamp/puppet-openldap.git', '1.6.1')
  print_diff_module(agent, 'https://github.com/puppetlabs/puppetlabs-haproxy.git', '1.0.0')
  print_diff_module(agent, 'https://github.com/puppetlabs/puppetlabs-concat.git', '1.1.1')
  print_diff_module(agent, 'https://github.com/puppetlabs/puppetlabs-stdlib.git', '4.13.1')
  print_diff_module(agent, 'https://github.com/puppetlabs/puppetlabs-apache.git', '1.5.0')
  print_diff_module(agent, 'https://github.com/puppetlabs/puppetlabs-inifile.git', '1.2.0')
  print_diff_module(agent, 'https://github.com/pdxcat/puppet-module-collectd.git', 'v3.4.0')

  step 'test core facts without filter' do
    facts_file_path = ''
    if agent['platform'] =~ /windows/
      facts_file_path = '/cygdrive/c/Program Files/Puppet Labs/Puppet/puppet/lib/ruby/vendor_ruby/puppet/face/facts.rb'
    else
      on(agent, 'find / -name facts.rb', :accept_all_exit_codes => true) do |result|
        result.stdout.each_line do |line|
          facts_file_path = line.chomp
          break if line.include?('face')
        end
      end
    end

    dif_file_path = ''
    if agent['platform'] =~ /windows/
      dif_file_path = '/cygdrive/c/Program Files/Puppet Labs/Puppet/puppet/lib/ruby/vendor_ruby/puppet/util/fact_dif.rb'
    else
      on(agent, 'find / -name fact_dif.rb', :accept_all_exit_codes => true) do |result|
        result.stdout.each_line do |line|
          dif_file_path = line.chomp
          break if line.include?('util')
        end
      end
    end

    puts "DEBUG: path found is '#{facts_file_path}'"
    puts "DEBUG: path found is '#{dif_file_path}'"

    original_fact_output = ''
    on agent, "cat '#{facts_file_path}'" do |result|
      original_fact_output = result.stdout
    end

    original_dif_output = ''
    on agent, "cat '#{dif_file_path}'" do |result|
      original_dif_output = result.stdout
    end

    create_remote_file agent, facts_file_path, %{
require 'puppet/indirector/face'
require 'puppet/node/facts'
require 'puppet/util/fact_dif'

EXCLUDE_LIST = %w[]

Puppet::Indirector::Face.define(:facts, '0.0.1') do
  copyright "Puppet Inc.", 2011
  license   _("Apache 2 license; see COPYING")

  summary _("Retrieve and store facts.")
  description <<-'EOT'
    This subcommand manages facts, which are collections of normalized system
    information used by Puppet. It can read facts directly from the local system
    (with the default `facter` terminus).
  EOT

  find = get_action(:find)
  find.summary _("Retrieve a node's facts.")
  find.arguments _("[<node_certname>]")
  find.returns <<-'EOT'
    A hash containing some metadata and (under the "values" key) the set
    of facts for the requested node. When used from the Ruby API: A
    Puppet::Node::Facts object.
    RENDERING ISSUES: Facts cannot currently be rendered as a string; use yaml
    or json.
  EOT
  find.notes <<-'EOT'
    When using the `facter` terminus, the host argument is ignored.
  EOT
  find.examples <<-'EOT'
    Get facts from the local system:
    $ puppet facts find
  EOT
  find.default = true

  deactivate_action(:destroy)
  deactivate_action(:search)

  action(:upload) do
    summary _("Upload local facts to the puppet master.")
    description <<-'EOT'
      Reads facts from the local system using the `facter` terminus, then
      saves the returned facts using the rest terminus.
    EOT
    returns "Nothing."
    notes <<-'EOT'
      This action requires that the puppet master's `auth.conf` file
      allow `PUT` or `save` access to the `/puppet/v3/facts` API endpoint.
      For details on configuring Puppet Server's `auth.conf`, see:
      <https://puppet.com/docs/puppetserver/latest/config_file_auth.html>
      For legacy Rack-based Puppet Masters, see:
      <https://puppet.com/docs/puppet/latest/config_file_auth.html>
    EOT
    examples <<-'EOT'
      Upload facts:
      $ puppet facts upload
    EOT

    render_as :json

    when_invoked do |options|
      # Use `agent` sections  settings for certificates, Puppet Server URL,
      # etc. instead of `user` section settings.
      Puppet.settings.preferred_run_mode = :agent
      Puppet::Node::Facts.indirection.terminus_class = :facter

      facts = Puppet::Node::Facts.indirection.find(Puppet[:node_name_value])
      unless Puppet[:node_name_fact].empty?
        Puppet[:node_name_value] = facts.values[Puppet[:node_name_fact]]
        facts.name = Puppet[:node_name_value]
      end

      client = Puppet.runtime[:http]
      session = client.create_session
      puppet = session.route_to(:puppet)

      Puppet.notice(_("Uploading facts for '%{node}' to '%{server}'") % {
                    node: Puppet[:node_name_value],
                    server: puppet.url.hostname})

      puppet.put_facts(Puppet[:node_name_value], facts: facts, environment: Puppet.lookup(:current_environment).name.to_s)
      nil
    end
  end

  action(:diff) do
    summary _("Compare Facter 3 output with Facter 4 output")
    description <<-'EOT'
    Compares output from facter 3 with Facter 4 and prints the differences
    EOT
    returns "Differences between Facter 3 and Facter 4 output as an array."
    notes <<-'EOT'
    EOT
    examples <<-'EOT'
    get differences between facter versions:
    $ puppet facts diff
    EOT

    render_as :json

    when_invoked do |*args|
      Puppet.settings.preferred_run_mode = :agent
      Puppet::Node::Facts.indirection.terminus_class = :facter

      if Puppet::Util::Package.versioncmp(Facter.value('facterversion'), '4.0.0') < 0
        cmd_flags = '--render-as json --show-legacy'

        # puppet/ruby are in PATH since it was updated in the wrapper script
        puppet_show_cmd  = "puppet facts show"
        if Puppet::Util::Platform.windows?
          puppet_show_cmd = "ruby -S -- \#\{puppet_show_cmd\}"
        end

        facter_3_result = Puppet::Util::Execution.execute("\#\{puppet_show_cmd\} --no-facterng \#\{cmd_flags\}")
        facter_ng_result = Puppet::Util::Execution.execute("\#\{puppet_show_cmd\} --facterng \#\{cmd_flags\}")

        fact_diff = FactDif.new(facter_3_result, facter_ng_result, EXCLUDE_LIST)
        fact_diff.difs
      else
        Puppet.warning _("Already using Facter 4. To use `puppet facts diff` remove facterng from the .conf file or run `puppet config set facterng false`.")
        exit 0
      end
    end
  end

  action(:show) do
    summary _("Retrieve current node's facts.")
    arguments _("[<facts>]")
    description <<-'EOT'
    Reads facts from the local system using `facter` terminus.
    A query can be provided to retrieve just a specific fact or a set of facts.
    EOT
    returns "The output of facter with added puppet specific facts."
    notes <<-'EOT'
    EOT
    examples <<-'EOT'
    retrieve facts:
    $ puppet facts show os
    EOT

    option("--config-file " + _("<path>")) do
      default_to { nil }
      summary _("The location of the config file for Facter.")
    end

    option("--custom-dir " + _("<path>")) do
      default_to { nil }
      summary _("The path to a directory that contains custom facts.")
    end

    option("--external-dir " + _("<path>")) do
      default_to { nil }
      summary _("The path to a directory that contains external facts.")
    end

    option("--no-block") do
      summary _("Disable fact blocking mechanism.")
    end

    option("--no-cache") do
      summary _("Disable fact caching mechanism.")
    end

    option("--show-legacy") do
      summary _("Show legacy facts when querying all facts.")
    end

    option("--value-only") do
      summary _("Show only the value when the action is called with a single query")
    end

    when_invoked do |*args|
      options = args.pop

      Puppet.settings.preferred_run_mode = :agent
      Puppet::Node::Facts.indirection.terminus_class = :facter

      if options[:value_only] && !args.count.eql?(1)
        options[:value_only] = nil
        Puppet.warning("Incorrect use of --value-only argument; it can only be used when querying for a single fact!")
      end

      options[:user_query] = args
      options[:resolve_options] = true
      result = Puppet::Node::Facts.indirection.find(Puppet.settings[:certname], options)

      if options[:value_only]
        result.values.values.first
      else
        result.values
      end
    end

    when_rendering :console do |result|
      # VALID_TYPES = [Integer, Float, TrueClass, FalseClass, NilClass, Symbol, String, Array, Hash].freeze
      # from https://github.com/puppetlabs/facter/blob/4.0.49/lib/facter/custom_facts/util/normalization.rb#L8

      case result
      when Array, Hash
        Puppet::Util::Json.dump(result, :pretty => true)
      else # one of VALID_TYPES above
        result
      end
    end
  end
end
}

create_remote_file agent, dif_file_path, %{
require 'json'

class FactDif
  def initialize(old_output, new_output, exclude_list = [])
    @c_facter = JSON.parse(old_output)
    @next_facter = JSON.parse(new_output)
    @exclude_list = exclude_list
    @diff = \{\}
  end

  def difs
    search_hash(@c_facter, [])

    @diff
  end

  private

  def search_hash(sh, path = [])
    if sh.is_a?(Hash)
      sh.each do |k, v|
        search_hash(v, path.push(k))
        path.pop
      end
    elsif sh.is_a?(Array)
      sh.each_with_index do |v, index|
        search_hash(v, path.push(index))
        path.pop
      end
    else
      compare(path, sh)
    end
  end

  def compare(fact_path, old_value)
    new_value = @next_facter.dig(*fact_path)
    if different?(new_value, old_value) && !excluded?(fact_path.join('.'))
      @diff[fact_path.join('.')] = { new_value: new_value, old_value: old_value }
    end
  end

  def different?(new, old)
    if old.is_a?(String) && new.is_a?(String)
      old_values = old.split(',')
      new_values = new.split(',')

      diff = old_values - new_values
      # also add new entries only available in Facter 4
      diff.concat(new_values - old_values)

      return true if diff.any?

      return false
    end

    old != new
  end

  def excluded?(fact_name)
    @exclude_list.any? \{\|excluded_fact\| fact_name =~ /^\#\{excluded_fact\}$/\}
  end
end
}

    print_diff(agent, "core_facts_unfiltered", "Puppet@6.x(commit:#{$puppet_commit}),Facter@main(commit:#{$facter_ng_commit}),cFacter@#{$facter3_version}")

    create_remote_file agent, facts_file_path, original_fact_output
    create_remote_file agent, facts_file_path, original_dif_output
  end
end
