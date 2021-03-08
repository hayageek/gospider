package core

import "testing"

var domain = "yahoo.com"

func TestOtherSources(t *testing.T) {
	urls := OtherSources(domain, false,1)
	t.Log(len(urls))
	t.Log(urls)
}

func TestGetCommonCrawlURLs(t *testing.T) {
	urls, err := getCommonCrawlURLs(domain, false,1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(len(urls))
	t.Log(urls)
}

func TestGetVirusTotalURLs(t *testing.T) {
	urls, err := getVirusTotalURLs(domain, false,1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(len(urls))
	t.Log(urls)
}

func TestGetWaybackURLs(t *testing.T) {
	urls, err := getWaybackURLs(domain, false,1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(len(urls))
	t.Log(urls)
}

func TestGetOtxUrls(t *testing.T) {
	urls, err := getOtxUrls(domain, false,1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(len(urls))
	t.Log(urls)
}
