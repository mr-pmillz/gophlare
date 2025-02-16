package utils

import (
	"strings"
	"testing"
)

func TestRemoveDuplicateStr(t *testing.T) {
	type args struct {
		strSlice []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{name: "no duplicates", args: args{strSlice: []string{"a", "b", "c"}}, want: []string{"a", "b", "c"}},
		{name: "with duplicates", args: args{strSlice: []string{"a", "b", "a", "c"}}, want: []string{"a", "b", "c"}},
		{name: "empty slice", args: args{strSlice: []string{}}, want: []string{}},
		{name: "all duplicates", args: args{strSlice: []string{"a", "a", "a"}}, want: []string{"a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RemoveDuplicateStr(tt.args.strSlice); !equalSlices(got, tt.want) {
				t.Errorf("RemoveDuplicateStr() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestSanitizeString(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{name: "sanitize single quotes", args: args{str: "test'value"}, want: "testvalue"},
		{name: "replace square brackets", args: args{str: "test[12345]value"}, want: "test_12345_value"},
		{name: "sanitize special characters", args: args{str: "*!@abc"}, want: "abc"},
		{name: "sanitize mixed characters", args: args{str: "!!!a-b*c def[ghi]! 123"}, want: "a_b_c_def_ghi_123"},
		{name: "trim underscores", args: args{str: "__test__"}, want: "test"},
		{name: "long input", args: args{str: strings.Repeat("a", 300)}, want: strings.Repeat("a", 255)},
		{name: "empty input", args: args{str: ""}, want: ""},
		{name: "only special characters", args: args{str: "!@#$%^&*()"}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeString(tt.args.str); got != tt.want {
				t.Errorf("SanitizeString() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestContainsExactMatch(t *testing.T) {
	type args struct {
		s   []string
		str string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "match exists", args: args{s: []string{"a", "b", "c"}, str: "b"}, want: true},
		{name: "no match", args: args{s: []string{"a", "b", "c"}, str: "d"}, want: false},
		{name: "case insensitive match", args: args{s: []string{"A", "B", "C"}, str: "b"}, want: false},
		{name: "empty slice", args: args{s: []string{}, str: "a"}, want: false},
		{name: "empty string", args: args{s: []string{"a", "b", "c"}, str: ""}, want: false},
		{name: "numeric string match", args: args{s: []string{"1", "2", "3"}, str: "2"}, want: true},
		{name: "mixed string match", args: args{s: []string{"abc", "12abc", "xyz"}, str: "12abc"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsExactMatch(tt.args.s, tt.args.str); got != tt.want {
				t.Errorf("ContainsExactMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}
func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestIsUserIDFormatMatch(t *testing.T) {
	type args struct {
		credentialUsername string
		userIDFormat       string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "1 letter 5 numbers", args: args{credentialUsername: "z54321", userIDFormat: "a12345"}, want: true},
		{name: "2 letter 6 numbers", args: args{credentialUsername: "zz654321", userIDFormat: "aa123456"}, want: true},
		{name: "Domain backslash and 2 letter + 6 numbers", args: args{credentialUsername: "AA\\zz654321", userIDFormat: "ZZ\\aa123456"}, want: true},
		{name: "Domain backslash and leetspeak username", args: args{credentialUsername: "AA\\coolB34n5", userIDFormat: "ZZ\\31337Username"}, want: false}, // this won't match but that is okay as this would be too greedy of a match perhaps but can be refactored in needed.
		{name: "all letters pass", args: args{credentialUsername: "abcd", userIDFormat: "aaaa"}, want: true},
		{name: "numbers only", args: args{credentialUsername: "1234", userIDFormat: "1111"}, want: true},
		{name: "letters and numbers", args: args{credentialUsername: "a1b2", userIDFormat: "a1a1"}, want: true},
		{name: "special character mismatch", args: args{credentialUsername: "a1b2$", userIDFormat: "a1a1%"}, want: false},
		{name: "empty credentialUsername", args: args{credentialUsername: "", userIDFormat: "a1a1"}, want: false},
		{name: "empty userIDFormat", args: args{credentialUsername: "a1b2", userIDFormat: ""}, want: false},
		{name: "both empty", args: args{credentialUsername: "", userIDFormat: ""}, want: true},
		{name: "special character mismatch", args: args{credentialUsername: "a1b2!", userIDFormat: "a1a1a"}, want: false},
		{name: "format mismatch", args: args{credentialUsername: "abc", userIDFormat: "111"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsUserIDFormatMatch(tt.args.credentialUsername, tt.args.userIDFormat); got != tt.want {
				t.Errorf("IsUserIDFormatMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractBaseDomain(t *testing.T) {
	type args struct {
		target string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "test URL ip", args: args{target: "https://192.168.1.1"}, want: "", wantErr: false},
		{name: "test URL hostname", args: args{target: "https://foo.example.com"}, want: "example.com", wantErr: false},
		{name: "test URL hostname trailing forward slash", args: args{target: "https://foo.example.com/"}, want: "example.com", wantErr: false},
		{name: "test URL foo.co.uk", args: args{target: "https://foo.co.uk"}, want: "foo.co.uk", wantErr: false},
		{name: "test URL:PORT", args: args{target: "https://example.com.au:9001/"}, want: "example.com.au", wantErr: false},
		{name: "malformed URL", args: args{target: "://example.com"}, want: "", wantErr: false},
		{name: "empty input", args: args{target: ""}, want: "", wantErr: false},
		{name: "localhost", args: args{target: "http://localhost"}, want: "localhost", wantErr: false},
		{name: "multiple subdomains", args: args{target: "https://sub1.sub2.example.com"}, want: "example.com", wantErr: false},
		{name: "test cool.barbaz.co.uk", args: args{target: "cool.barbaz.co.uk"}, want: "barbaz.co.uk", wantErr: false},
		{name: "test co.uk", args: args{target: "co.uk"}, want: "co.uk", wantErr: false},
		{name: "test foo.co.uk", args: args{target: "foo.co.uk"}, want: "foo.co.uk", wantErr: false},
		{name: "test foo.example.com", args: args{target: "foo.example.com"}, want: "example.com", wantErr: false},
		{name: "test api.foo.bar.co.uk", args: args{target: "api.foo.bar.co.uk"}, want: "api.foo.bar.co.uk", wantErr: false},
		{name: "test api.asdfasdf.asdfadfasdfasdf.co.uk", args: args{target: "api.asdfasdf.asdfadfasdfasdf.co.uk"}, want: "asdfadfasdfasdf.co.uk", wantErr: false},
		{name: "test cool.example.edu", args: args{target: "cool.example.edu"}, want: "example.edu", wantErr: false},
		{name: "test example.com.au", args: args{target: "example.com.au"}, want: "example.com.au", wantErr: false},
		{name: "test api.cool.example.com", args: args{target: "api.cool.example.com"}, want: "example.com", wantErr: false},
		{name: "test fun.cool.qa.foo.example.com", args: args{target: "fun.cool.qa.foo.example.com"}, want: "example.com", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractBaseDomain(tt.args.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractBaseDomain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ExtractBaseDomain() got = %v, want %v", got, tt.want)
			} else {
				t.Logf("ExtractBaseDomain() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_hasBaseDomainWithoutTLDPrefix(t *testing.T) {
	type args struct {
		credentialUsername string
		domain             string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "credential has base domain prefix without tld underscore", args: args{credentialUsername: "example_testing", domain: "example.com"}, want: true},
		{name: "credential has base domain prefix without tld", args: args{credentialUsername: "example-10a", domain: "example.com"}, want: true},
		{name: "credential matches base domain without TLD", args: args{credentialUsername: "exampleuser", domain: "example.com"}, want: true},
		{name: "credential doesn't match base domain without TLD", args: args{credentialUsername: "anotheruser", domain: "example.com"}, want: false},
		{name: "base domain extraction fails", args: args{credentialUsername: "exampleuser", domain: "://invalid-url"}, want: false},
		{name: "base domain has less than two parts", args: args{credentialUsername: "localhostuser", domain: "localhost"}, want: false},
		{name: "credential matches domain exactly without TLD", args: args{credentialUsername: "example", domain: "example.com"}, want: true},
		{name: "empty credential and domain", args: args{credentialUsername: "", domain: ""}, want: false},
		{name: "unrelated credential username", args: args{credentialUsername: "unrelateduser", domain: "example.com"}, want: false},
		{name: "empty base domain", args: args{credentialUsername: "exampleuser", domain: ""}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasBaseDomainWithoutTLDPrefix(tt.args.credentialUsername, tt.args.domain); got != tt.want {
				t.Errorf("HasBaseDomainWithoutTLDPrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}
