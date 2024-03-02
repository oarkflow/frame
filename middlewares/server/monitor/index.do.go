package monitor

import (
	"strconv"
	"strings"
	"time"
)

type viewBag struct {
	title      string
	fontURL    string
	chartJSURL string
	customHead string
	refresh    time.Duration
}

// returns index with new title/refresh
func newIndex(dat viewBag) string {
	timeout := dat.refresh.Milliseconds() - timeoutDiff
	if timeout < timeoutDiff {
		timeout = timeoutDiff
	}
	ts := strconv.FormatInt(timeout, 10)
	replacer := strings.NewReplacer("$TITLE", dat.title, "$TIMEOUT", ts,
		"$FONT_URL", dat.fontURL, "$CHART_JS_URL", dat.chartJSURL, "$CUSTOM_HEAD", dat.customHead,
	)
	return replacer.Replace(indexHTML)
}

const (
	defaultTitle = "Frame Monitor"

	defaultRefresh    = 3 * time.Second
	timeoutDiff       = 200 // timeout will be Refresh (in milliseconds) - timeoutDiff
	minRefresh        = timeoutDiff * time.Millisecond
	defaultFontURL    = `https://fonts.googleapis.com/css2?family=Roboto:wght@400;900&display=swap`
	defaultChartJSURL = `https://cdn.jsdelivr.net/npm/chart.js@2.9/dist/Chart.bundle.min.js`
	defaultCustomHead = ``

	// parametrized by $TITLE and $TIMEOUT
	indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<link href="$FONT_URL" rel="stylesheet">
	<script src="$CHART_JS_URL"></script>

	<title>$TITLE</title>
<style>
    :root {
      --grey-d1: #585858;
      --grey-d2: #F4F4F4;
      --grey-d3: #000000;
      --red-1: #F2B8D1;
      --red-2: #F04B92;
      --red-3: #EB1E77;
      --red-4: #AD1257;
      --white: #FFFFFF;
      --blue: #329EF4;
      --grey: #eeeeee;
    }
    html,
    body {
      font-family: sans-serif;
      height: 100%;
      background-color: var(--grey);
    }
	.monitor-data{color: var(--grey-d1); font-size: 0.8em;}
    .card {
      background-color: white;
      border-radius: 5px;
      box-shadow: 2px 2px 5px 2px #D7D7D7;
    }
    .chart-lbl {
      margin: 15px;
      color: var(--grey-d3);
      opacity: 0.8;
    }
    h4 {
      font-size: 16px;
      font-weight: bold;
    }
    .divider {
      background-color: var(--grey-d2);
      height: 2px;
      margin: auto;
      width: 98%;
    }
    .container {
      margin: 15px auto;
    }
    .dashboard-container {
      display: grid;
      grid-template: 33% / 100%;
      grid-gap: 20px;
    }
    .divider + div {
      padding: 15px;
    }

    @media only screen and (min-width: 992px) {
      .dashboard-container {
        grid-template: 19% 19% 19% 10% 10% 10% / repeat(2, 50%);
      }
    }
    @media only screen and (min-width: 1200px) {
      .dashboard-container {
        grid-template: repeat(5, 1fr) / repeat(11, 1fr);
        grid-gap: 10px;
        margin: 0;
        padding: 15px;
      }
      .container {
        max-width: 1500px;
      }
    }
    @media screen and (min-width: 1500px) {
      .dashboard-container {
        max-width: 1500px;
      }
    }
	.flex{display: flex;}
	.justify-between{justify-content: space-between;}
$CUSTOM_HEAD
</style>
</head>
<body>
<div class="container">
	<h4>$TITLE</h4>
    <div class="dashboard-container">
      <div class="card">
        <h4 class="chart-lbl flex justify-between">
		<span>CPU Usage</span>
		<span class="monitor-data" id="cpuMetric">0.00%</span>
		</h4>
        <div class="divider">
        </div>
        <div class="doughnut-chart-container">
          <canvas id="cpuChart"></canvas>
        </div>
      </div>
      <div class="card">
        <h4 class="chart-lbl flex justify-between">
			<span>Memory Usage</span>
			<span class="monitor-data" id="ramMetric" title="PID used / OS used / OS total">0.00 MB</span>
		</h4>
        <div class="divider">
        </div>
        <div class="pie-chart-container">
          <canvas id="ramChart"></canvas>
        </div>
      </div>
      <div class="card">
        <h4 class="chart-lbl flex justify-between">
			<span>Response Time</span>
			<span class="monitor-data" id="rtimeMetric">0ms</span>
		</h4>
        <div class="divider">
        </div>
        <div class="bar-chart-container">
          <canvas id="rtimeChart"></canvas>
        </div>
      </div>
      <div class="card">
        <h4 class="chart-lbl flex justify-between">
			<span>Open Connections</span>
			<span class="monitor-data" id="connsMetric">0</span>
		</h4>
        <div class="divider">
        </div>
        <div class="bar-chart-container">
          <canvas id="connsChart"></canvas>
        </div>
      </div>
    </div>
  </div>
<script>
	function formatBytes(bytes, decimals = 1) {
		if (bytes === 0) return '0 Bytes';

		const k = 1024;
		const dm = decimals < 0 ? 0 : decimals;
		const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

		const i = Math.floor(Math.log(bytes) / Math.log(k));

		return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
	}
	Chart.defaults.global.legend.display = false;
	Chart.defaults.global.defaultFontSize = 8;
	Chart.defaults.global.animation.duration = 1000;
	Chart.defaults.global.animation.easing = 'easeOutQuart';
	Chart.defaults.global.elements.line.backgroundColor = 'rgba(0, 172, 215, 0.25)';
	Chart.defaults.global.elements.line.borderColor = 'rgba(0, 172, 215, 1)';
	Chart.defaults.global.elements.line.borderWidth = 2;

	const options = {
		scales: {
			yAxes: [{ ticks: { beginAtZero: true }}],
			xAxes: [{
				type: 'time',
				time: {
					unitStepSize: 30,
					unit: 'second'
				},
				gridlines: { display: false }
			}]
		},
		tooltips: {	enabled: false },
		responsive: true,
		maintainAspectRatio: false,
		animation: false
	};
	const cpuMetric = document.querySelector('#cpuMetric');
	const ramMetric = document.querySelector('#ramMetric');
	const rtimeMetric = document.querySelector('#rtimeMetric');
	const connsMetric = document.querySelector('#connsMetric');

	const cpuChartCtx = document.querySelector('#cpuChart').getContext('2d');
	const ramChartCtx = document.querySelector('#ramChart').getContext('2d');
	const rtimeChartCtx = document.querySelector('#rtimeChart').getContext('2d');
	const connsChartCtx = document.querySelector('#connsChart').getContext('2d');

	const cpuChart = createChart(cpuChartCtx);
	const ramChart = createChart(ramChartCtx);
	const rtimeChart = createChart(rtimeChartCtx);
	const connsChart = createChart(connsChartCtx);

	const charts = [cpuChart, ramChart, rtimeChart, connsChart];

	function createChart(ctx) {
		return new Chart(ctx, {
			type: 'line',
			data: {
				labels: [],
				datasets: [{
					label: '',
					data: [],
					lineTension: 0.2,
					pointRadius: 0,
				}]
			},
			options
		});
	}
	ramChart.data.datasets.push({
		data: [],
		lineTension: 0.2,
		pointRadius: 0,
		backgroundColor: 'rgba(255, 200, 0, .6)',
		borderColor: 'rgba(255, 150, 0, .8)',
	})
	ramChart.data.datasets.push({
		data: [],
		lineTension: 0.2,
		pointRadius: 0,
		backgroundColor: 'rgba(0, 255, 0, .4)',
		borderColor: 'rgba(0, 200, 0, .8)',
	})
	function update(json, rtime) {
		cpu = json.pid.cpu.toFixed(1);
		cpuOS = json.os.cpu.toFixed(1);

		cpuMetric.innerHTML = '<span title="Application CPU Usage">' + cpu + '%</span> <span style="font-size:12px;"> / </span> <span title="Total CPU Usage" style="font-size:12px;">' + cpuOS + '%</span>';
		ramMetric.innerHTML = '<span title="Application Memory Usage">' + formatBytes(json.pid.ram) + '</span><span style="font-size:12px;"> / </span><span title="OS Memory Usage" class="ram_os" style="font-size:12px;">' + formatBytes(json.os.ram) +
			'<span><span style="font-size:12px;"> / </span><span class="ram_total" style="font-size:12px;" title="Total Memory">' + formatBytes(json.os.total_ram) + '</span>';
		rtimeMetric.innerHTML = '<span title="Response Time">' + rtime + 'ms</span>';
		connsMetric.innerHTML = '<span title="Application Connections">' + json.pid.conns + '</span> <span style="font-size:12px;"> / </span> <span style="font-size:12px;" title="Total Connections">' + json.os.conns + '</span>';

		cpuChart.data.datasets[0].data.push(cpu);
		ramChart.data.datasets[2].data.push((json.os.total_ram / 1e6).toFixed(2));
		ramChart.data.datasets[1].data.push((json.os.ram / 1e6).toFixed(2));
		ramChart.data.datasets[0].data.push((json.pid.ram / 1e6).toFixed(2));
		rtimeChart.data.datasets[0].data.push(rtime);
		connsChart.data.datasets[0].data.push(json.pid.conns);

		const timestamp = new Date().getTime();

		charts.forEach(chart => {
			if (chart.data.labels.length > 50) {
				chart.data.datasets.forEach(function (dataset) { dataset.data.shift(); });
				chart.data.labels.shift();
			}
			chart.data.labels.push(timestamp);
			chart.update();
		});
		setTimeout(fetchJSON, $TIMEOUT)
	}
	function fetchJSON() {
		var t1 = ''
		var t0 = performance.now()
		fetch(window.location.href, {
				headers: { 'Accept': 'application/json' },
				credentials: 'same-origin'
			})
			.then(res => {
				t1 = performance.now()
				return res.json()
			})
			.then(res => { update(res, Math.round(t1 - t0)) })
			.catch(console.error);
	}
	fetchJSON()
</script>
</body>
</html>
`
)
