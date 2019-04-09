require 'erb'

module Bundler
  module Audit
    module Presenter
      class Junit < Base
        def print_report
          puts ERB.new(template_string, nil, '-').result(binding)
        end

        protected

        def advisory_ref(advisory)
          if advisory.cve
            xml_escape "CVE-#{advisory.cve}"
          elsif advisory.osvdb
            xml_escape advisory.osvdb
          end
        end

        def advisory_criticality(advisory)
          case advisory.criticality
          when :low    then "Low"
          when :medium then "Medium"
          when :high   then "High"
          else              "Unknown"
          end
        end

        def advisory_solution(advisory)
          unless advisory.patched_versions.empty?
            xml_escape "upgrade to #{advisory.patched_versions.join(', ')}"
          else
            "remove or disable this gem until a patch is available!"
          end
        end

        def bundle_title(bundle)
          xml_escape "#{advisory_criticality(bundle.advisory).upcase} #{bundle.gem.name}(#{bundle.gem.version}) #{bundle.advisory.title}"
        end

        def xml_escape(string)
          string.gsub(
            /[<>"'&]/,
            '<' => '&lt;',
            '>' => '&gt;',
            '"' => '&quot;',
            '\'' => '&apos;',
            '&' => '&amp;',
          )
        end

        def template_string
          <<-HERE.strip
<?xml version="1.0" encoding="UTF-8" ?>
<testsuites id="<%= Time.now.to_i %>" name="Bundle Audit" tests="225" failures="1262">
  <testsuite id="Gemfile" name="Ruby Gemfile" failures="<%= @advisory_bundles.size %>">
    <%- @advisory_bundles.each do |bundle| -%>
    <testcase id="<%= xml_escape(bundle.gem.name) %>" name="<%= bundle_title(bundle) %>">
      <failure message="<%= xml_escape(bundle.advisory.title) %>" type="<%= xml_escape(bundle.advisory.criticality) %>">
Name: <%= xml_escape(bundle.gem.name) %>
Version: <%= xml_escape(bundle.gem.version) %>
Advisory: <%= advisory_ref(bundle.advisory) %>
Criticality: <%= advisory_criticality(bundle.advisory) %>
URL: <%= xml_escape(bundle.advisory.url) %>
Title: <%= xml_escape(bundle.advisory.title) %>
Solution: <%= advisory_solution(bundle.advisory) %>
      </failure>
    </testcase>
    <%- end -%>
  </testsuite>
</testsuites>
          HERE
        end
      end
    end
  end
end
