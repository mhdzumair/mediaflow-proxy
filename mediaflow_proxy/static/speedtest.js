// Speed test functionality
class MediaFlowSpeedTest {
    constructor() {
        this.config = null;
        this.results = {
            proxy: {},
            direct: {}
        };
        this.servers = [];
        this.currentTestIndex = 0;
        this.totalTests = 0;
        this.charts = {};
        this.testCancelled = false;
        this.selectedCdns = new Set();
        this.activeAbortControllers = new Set();

        this.initializeEventListeners();
        this.initializeForm();
        this.setupResizeHandler();
    }

    initializeEventListeners() {
        document.getElementById('configForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.startSpeedTest();
        });

        document.getElementById('provider').addEventListener('change', (e) => {
            const apiKeySection = document.getElementById('apiKeySection');
            if (e.target.value === 'all_debrid') {
                apiKeySection.classList.remove('hidden');
            } else {
                apiKeySection.classList.add('hidden');
            }

            // Clear CDN selection when provider changes
            this.config = null;
            this.selectedCdns.clear();
            this.showPlaceholderCdnSelection();
            this.updateCdnButtonStates();
        });

        document.getElementById('addServerBtn').addEventListener('click', () => {
            this.addServerInput();
        });

        document.getElementById('runAgainBtn').addEventListener('click', () => {
            this.resetTest();
        });

        document.getElementById('cancelTestBtn').addEventListener('click', () => {
            this.cancelTest();
        });

        document.getElementById('selectAllCdn').addEventListener('click', () => {
            this.selectAllCdns(true);
        });

        document.getElementById('selectNoneCdn').addEventListener('click', () => {
            this.selectAllCdns(false);
        });

        document.getElementById('refreshCdnBtn').addEventListener('click', async () => {
            await this.refreshCdnLocations();
        });

        // Handle server removal
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('remove-server')) {
                e.target.closest('.server-input').remove();
                this.updateRemoveButtons();
            }
        });
    }

    initializeForm() {
        // Set current URL as default MediaFlow URL
        const currentUrl = new URL(window.location.href);
        const baseUrl = `${currentUrl.protocol}//${currentUrl.host}`;
        const firstServerUrl = document.querySelector('.server-url');
        firstServerUrl.value = baseUrl;
        firstServerUrl.placeholder = `${baseUrl} (Current Instance)`;

        // Show placeholder CDN selection initially
        this.showPlaceholderCdnSelection();
        this.updateCdnButtonStates();
    }

    showPlaceholderCdnSelection() {
        const cdnStatusContainer = document.getElementById('cdnStatusContainer');
        const cdnContainer = document.getElementById('cdnSelection');

        // Clear status container
        cdnStatusContainer.innerHTML = '';

        // Show placeholder in main CDN container
        cdnContainer.innerHTML = `
                    <div class="col-span-full text-center py-8 border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-800">
                        <div class="text-4xl mb-4">🌐</div>
                        <h3 class="text-lg font-semibold text-gray-700 dark:text-gray-300 mb-2">CDN Locations Not Loaded</h3>
                        <p class="text-gray-500 dark:text-gray-400 mb-4">
                            Configure your debrid provider settings above, then click "🔄 Refresh CDNs" to load available locations.
                        </p>
                        <div class="text-sm text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20 rounded-lg p-3 mx-auto max-w-md">
                            <strong>Steps:</strong><br>
                            1. Select your debrid provider<br>
                            2. Enter API key (if required)<br>
                            3. Click "🔄 Refresh CDNs"<br>
                            4. Select desired locations<br>
                            5. Start speed test
                        </div>
                    </div>
                `;
    }

    addServerInput() {
        const container = document.getElementById('serversContainer');
        const serverDiv = document.createElement('div');
        serverDiv.className = 'server-input grid grid-cols-1 md:grid-cols-3 gap-3 p-3 bg-gray-50 dark:bg-gray-700 rounded-lg';

        serverDiv.innerHTML = `
                    <input
                        type="url"
                        placeholder="MediaFlow URL"
                        class="server-url w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                        required
                    >
                    <input
                        type="text"
                        placeholder="Server Name (optional)"
                        class="server-name w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                    >
                    <div class="flex gap-2">
                        <input
                            type="password"
                            placeholder="API Password (optional)"
                            class="server-password flex-1 px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                        >
                        <button
                            type="button"
                            class="remove-server px-2 py-2 bg-red-500 text-white rounded-md hover:bg-red-600 focus:outline-none text-sm"
                        >
                            ×
                        </button>
                </div>
            `;

        container.appendChild(serverDiv);
        this.updateRemoveButtons();
    }

    updateRemoveButtons() {
        const serverInputs = document.querySelectorAll('.server-input');
        serverInputs.forEach((input, index) => {
            const removeBtn = input.querySelector('.remove-server');
            if (index === 0) {
                removeBtn.classList.add('hidden');
            } else {
                removeBtn.classList.remove('hidden');
            }
        });
    }

    async startSpeedTest() {
        try {
            this.testCancelled = false;

            // Check if CDN configuration is loaded
            if (!this.config || !this.config.test_urls) {
                alert('Please fetch CDN locations first by clicking "🔄 Refresh CDNs" button.');
                return;
            }

            // Collect server configurations
            this.collectServerConfigurations();

            // Validate server configurations
            if (this.servers.length === 0) {
                alert('Please add at least one MediaFlow server to test.');
                return;
            }

            // Validate CDN selections
            if (this.selectedCdns.size === 0) {
                alert('Please select at least one CDN location to test.');
                return;
            }

            // Validate test options
            const testProxy = document.getElementById('testProxy').checked;
            const testDirect = document.getElementById('testDirect').checked;

            if (!testProxy && !testDirect) {
                alert('Please select at least one test option (Proxy or Direct).');
                return;
            }

            // Calculate total tests
            this.calculateTotalTests();

            this.showTestingView();
            await this.runTests();
            if (!this.testCancelled) {
                this.showResults();
            }
        } catch (error) {
            console.error('Speed test failed:', error);
            if (!this.testCancelled) {
                alert('Speed test failed: ' + error.message);
                this.resetTest();
            }
        }
    }

    collectServerConfigurations() {
        // Collect server configurations
        this.servers = [];
        const serverInputs = document.querySelectorAll('.server-input');

        serverInputs.forEach(input => {
            const url = input.querySelector('.server-url').value.trim();
            const name = input.querySelector('.server-name').value.trim();
            const password = input.querySelector('.server-password').value.trim();

            if (url) {
                this.servers.push({
                    url: url,
                    name: name || new URL(url).host,
                    api_password: password || null
                });
            }
        });
    }

    async refreshCdnLocations() {
        const refreshBtn = document.getElementById('refreshCdnBtn');
        const originalText = refreshBtn.textContent;

        try {
            // Show loading state
            refreshBtn.textContent = '⏳ Loading...';
            refreshBtn.disabled = true;

            // Show loading in CDN container
            const cdnStatusContainer = document.getElementById('cdnStatusContainer');
            const cdnContainer = document.getElementById('cdnSelection');

            cdnStatusContainer.innerHTML = '';
            cdnContainer.innerHTML = `
                        <div class="col-span-full text-center py-8">
                            <div class="animate-spin text-4xl mb-4">⏳</div>
                            <p class="text-gray-600 dark:text-gray-400">Loading CDN locations...</p>
                        </div>
                    `;

            await this.loadConfiguration();
            this.populateCdnSelection();

            // Show success message
            const successMsg = document.createElement('div');
            successMsg.className = 'fixed top-4 right-4 bg-green-500 text-white px-4 py-2 rounded-lg shadow-lg z-50';
            successMsg.textContent = `✅ Loaded ${Object.keys(this.config.test_urls).length} CDN locations`;
            document.body.appendChild(successMsg);

            setTimeout(() => {
                successMsg.remove();
            }, 3000);

        } catch (error) {
            console.error('Failed to refresh CDN locations:', error);

            // Show error message
            const errorMsg = document.createElement('div');
            errorMsg.className = 'fixed top-4 right-4 bg-red-500 text-white px-4 py-2 rounded-lg shadow-lg z-50';
            errorMsg.textContent = `❌ Failed: ${error.message}`;
            document.body.appendChild(errorMsg);

            setTimeout(() => {
                errorMsg.remove();
            }, 5000);

            this.showPlaceholderCdnSelection();
            this.updateCdnButtonStates();
        } finally {
            // Restore button state
            refreshBtn.textContent = originalText;
            refreshBtn.disabled = false;
        }
    }

    cancelTest() {
        this.testCancelled = true;
        document.getElementById('currentTest').textContent = 'Test cancelled by user';
        document.getElementById('progressText').textContent = 'Cancelling...';

        // Cancel all active network requests
        this.activeAbortControllers.forEach(controller => {
            try {
                controller.abort();
            } catch (e) {
                console.warn('Error aborting request:', e);
            }
        });
        this.activeAbortControllers.clear();

        setTimeout(() => {
            this.resetTest();
        }, 1000);
    }

    populateCdnSelection() {
        const cdnStatusContainer = document.getElementById('cdnStatusContainer');
        const cdnContainer = document.getElementById('cdnSelection');
        const locations = Object.keys(this.config.test_urls);

        // Initialize all CDNs as selected if none are selected
        if (this.selectedCdns.size === 0) {
            locations.forEach(location => this.selectedCdns.add(location));
        }

        // Show success status
        cdnStatusContainer.innerHTML = `
                    <div class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4">
                        <div class="flex items-center space-x-2 text-green-700 dark:text-green-300">
                            <span class="text-lg">✅</span>
                            <span class="font-semibold">CDN Locations Loaded Successfully</span>
                            <span class="text-sm bg-green-200 dark:bg-green-800 px-2 py-1 rounded">${locations.length} locations</span>
                        </div>
                    </div>
                `;

        // Populate CDN checkboxes in the grid
        cdnContainer.innerHTML = locations.map(location => `
                    <div class="flex items-center space-x-2 p-3 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                        <input
                            type="checkbox"
                            id="cdn-${location}"
                            class="cdn-checkbox rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
                            ${this.selectedCdns.has(location) ? 'checked' : ''}
                            data-location="${location}"
                        >
                        <label for="cdn-${location}" class="text-sm font-medium text-gray-700 dark:text-gray-300 cursor-pointer flex-1">
                            ${location}
                        </label>
                    </div>
                `).join('');

        // Add event listeners to checkboxes
        document.querySelectorAll('.cdn-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                const location = e.target.dataset.location;
                this.toggleCdn(location);
            });
        });

        // Update button states
        this.updateCdnButtonStates();
    }

    toggleCdn(location) {
        if (this.selectedCdns.has(location)) {
            this.selectedCdns.delete(location);
        } else {
            this.selectedCdns.add(location);
        }
    }

    selectAllCdns(selectAll) {
        if (!this.config || !this.config.test_urls) {
            // Show a brief message if CDNs aren't loaded
            const message = document.createElement('div');
            message.className = 'fixed top-4 right-4 bg-yellow-500 text-white px-4 py-2 rounded-lg shadow-lg z-50';
            message.textContent = '⚠️ Please load CDN locations first';
            document.body.appendChild(message);
            setTimeout(() => message.remove(), 2000);
            return;
        }

        const checkboxes = document.querySelectorAll('.cdn-checkbox');
        const locations = Object.keys(this.config.test_urls);

        if (selectAll) {
            this.selectedCdns = new Set(locations);
            checkboxes.forEach(cb => cb.checked = true);
        } else {
            this.selectedCdns.clear();
            checkboxes.forEach(cb => cb.checked = false);
        }
    }

    updateCdnButtonStates() {
        const selectAllBtn = document.getElementById('selectAllCdn');
        const selectNoneBtn = document.getElementById('selectNoneCdn');
        const hasConfig = this.config && this.config.test_urls;

        if (hasConfig) {
            selectAllBtn.disabled = false;
            selectNoneBtn.disabled = false;
            selectAllBtn.classList.remove('opacity-50', 'cursor-not-allowed');
            selectNoneBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        } else {
            selectAllBtn.disabled = true;
            selectNoneBtn.disabled = true;
            selectAllBtn.classList.add('opacity-50', 'cursor-not-allowed');
            selectNoneBtn.classList.add('opacity-50', 'cursor-not-allowed');
        }
    }

    async loadConfiguration() {
        const provider = document.getElementById('provider').value;
        const apiKey = document.getElementById('apiKey').value;
        const currentApiPassword = document.getElementById('currentApiPassword').value;

        // Use current MediaFlow instance for fetching CDN configuration
        const currentUrl = new URL(window.location.href);
        const baseUrl = `${currentUrl.protocol}//${currentUrl.host}`;

        const requestBody = {
            provider: provider,
            api_key: apiKey || null,
            current_api_password: currentApiPassword || null
        };

        const headers = {
            'Content-Type': 'application/json',
        };

        // Build URL with api_password as query parameter if provided
        // This is more reliable than headers when behind reverse proxies
        let configUrl = '/speedtest/config';
        if (currentApiPassword) {
            configUrl += `?api_password=${encodeURIComponent(currentApiPassword)}`;
        }

        const response = await fetch(configUrl, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(requestBody)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to load configuration');
        }

        this.config = await response.json();
    }

    calculateTotalTests() {
        // Calculate total tests based on selected CDNs and servers
        const testProxy = document.getElementById('testProxy').checked;
        const testDirect = document.getElementById('testDirect').checked;
        const selectedLocationCount = this.selectedCdns.size;
        const serverCount = this.servers.length;

        this.totalTests = 0;
        if (testProxy) this.totalTests += selectedLocationCount * serverCount;
        if (testDirect) this.totalTests += selectedLocationCount;
    }

    showTestingView() {
        document.getElementById('configView').classList.add('hidden');
        document.getElementById('testingView').classList.remove('hidden');
        document.getElementById('resultsView').classList.add('hidden');

        // Clear previous results and any existing abort controllers
        this.results = {proxy: {}, direct: {}};
        this.activeAbortControllers.forEach(controller => {
            try {
                controller.abort();
            } catch (e) {
                console.warn('Error aborting request:', e);
            }
        });
        this.activeAbortControllers.clear();

        document.getElementById('liveResults').innerHTML = '';
    }

    showResults() {
        document.getElementById('configView').classList.add('hidden');
        document.getElementById('testingView').classList.add('hidden');
        document.getElementById('resultsView').classList.remove('hidden');

        this.renderMetrics();
        this.renderCharts();
        this.renderDetailedResults();
    }

    resetTest() {
        this.results = {proxy: {}, direct: {}};
        this.currentTestIndex = 0;
        this.totalTests = 0;
        this.testCancelled = false;

        // Cancel and clear any remaining abort controllers
        this.activeAbortControllers.forEach(controller => {
            try {
                controller.abort();
            } catch (e) {
                console.warn('Error aborting request:', e);
            }
        });
        this.activeAbortControllers.clear();

        // Destroy existing charts safely
        Object.values(this.charts).forEach(chart => {
            if (chart && typeof chart.destroy === 'function') {
                try {
                    chart.destroy();
                } catch (e) {
                    console.warn('Error destroying chart:', e);
                }
            }
        });
        this.charts = {};

        // Clear canvas elements
        ['speedChart', 'serverChart'].forEach(id => {
            const canvas = document.getElementById(id);
            if (canvas) {
                const ctx = canvas.getContext('2d');
                ctx.clearRect(0, 0, canvas.width, canvas.height);
            }
        });

        // Clear live results
        document.getElementById('liveResults').innerHTML = '';

        document.getElementById('configView').classList.remove('hidden');
        document.getElementById('testingView').classList.add('hidden');
        document.getElementById('resultsView').classList.add('hidden');
    }

    async runTests() {
        const testProxy = document.getElementById('testProxy').checked;
        const testDirect = document.getElementById('testDirect').checked;
        const testDuration = parseInt(document.getElementById('testDuration').value) || 10;

        this.currentTestIndex = 0;

        // Validate selected CDNs
        if (this.selectedCdns.size === 0) {
            throw new Error('Please select at least one CDN location to test');
        }

        // Filter test URLs to only selected CDNs
        const selectedTestUrls = Object.fromEntries(
            Object.entries(this.config.test_urls).filter(([location]) =>
                this.selectedCdns.has(location)
            )
        );

        // Run proxy tests for each server
        if (testProxy && !this.testCancelled) {
            for (const server of this.servers) {
                if (this.testCancelled) break;
                for (const [location, url] of Object.entries(selectedTestUrls)) {
                    if (this.testCancelled) break;
                    await this.runSingleTest(location, url, 'proxy', server, testDuration);
                }
            }
        }

        // Run direct tests
        if (testDirect && !this.testCancelled) {
            for (const [location, url] of Object.entries(selectedTestUrls)) {
                if (this.testCancelled) break;
                await this.runSingleTest(location, url, 'direct', null, testDuration);
            }
        }
    }

    async runSingleTest(location, url, testType, server, duration) {
        if (this.testCancelled) return;

        let testUrl;
        let testKey = location;

        if (testType === 'proxy') {
            testUrl = `${server.url.replace(/\/$/, '')}/proxy/stream?d=${encodeURIComponent(url)}`;
            if (server.api_password) {
                testUrl += `&api_password=${encodeURIComponent(server.api_password)}`;
            }
            testKey = `${location}_${server.name}`;
        } else {
            testUrl = url;
        }

        this.updateProgress(location, testType, server);

        try {
            const result = await this.measureSpeed(testUrl, duration);
            if (this.testCancelled) return;

            this.results[testType][testKey] = {
                ...result,
                server_url: url,
                test_url: testUrl,
                server_name: server ? server.name : 'Direct',
                location: location
            };

            this.updateLiveResults(testKey, testType, this.results[testType][testKey]);
        } catch (error) {
            if (this.testCancelled) return;

            // Don't log or update UI for cancelled tests
            if (error.message === 'Test cancelled') {
                return;
            }

            console.error(`Test failed for ${location} (${testType}):`, error);
            this.results[testType][testKey] = {
                error: error.message,
                server_url: url,
                test_url: testUrl,
                server_name: server ? server.name : 'Direct',
                location: location
            };

            this.updateLiveResults(testKey, testType, this.results[testType][testKey]);
        }

        this.currentTestIndex++;
    }

    async measureSpeed(url, duration) {
        const startTime = performance.now();
        let totalBytes = 0;

        // Create AbortController for this request
        const abortController = new AbortController();
        this.activeAbortControllers.add(abortController);

        try {
            // Check if test was cancelled before starting
            if (this.testCancelled) {
                throw new Error('Test cancelled');
            }

            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Range': 'bytes=0-'
                },
                signal: abortController.signal
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const reader = response.body.getReader();

            while (true) {
                // Check for cancellation in the reading loop
                if (this.testCancelled) {
                    reader.cancel();
                    throw new Error('Test cancelled');
                }

                const {done, value} = await reader.read();

                if (done) break;

                totalBytes += value.length;
                const currentTime = performance.now();

                // Check if duration exceeded
                if (currentTime - startTime >= duration * 1000) {
                    reader.cancel();
                    break;
                }
            }

            // Final cancellation check before returning results
            if (this.testCancelled) {
                throw new Error('Test cancelled');
            }

            const actualDuration = (performance.now() - startTime) / 1000;
            const speedMbps = (totalBytes * 8) / (actualDuration * 1_000_000);

            return {
                speed_mbps: Math.round(speedMbps * 100) / 100,
                duration: Math.round(actualDuration * 100) / 100,
                data_transferred: totalBytes,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            // If it's an abort error and test was cancelled, don't propagate the error
            if (error.name === 'AbortError' && this.testCancelled) {
                throw new Error('Test cancelled');
            }
            throw new Error(`Network error: ${error.message}`);
        } finally {
            // Clean up the abort controller
            this.activeAbortControllers.delete(abortController);
        }
    }

    updateProgress(location, testType, server) {
        const progress = this.totalTests > 0 ? (this.currentTestIndex / this.totalTests) * 100 : 0;
        const progressPercent = Math.min(Math.round(progress), 100); // Cap at 100%

        document.getElementById('progressBar').style.width = `${progressPercent}%`;
        document.getElementById('progressText').textContent = `${progressPercent}% complete`;

        const serverName = server ? server.name : 'Direct';
        document.getElementById('currentTest').textContent = `Testing ${location} via ${serverName} (${testType})...`;
    }

    updateLiveResults(testKey, testType, result) {
        const liveResults = document.getElementById('liveResults');

        let card = document.getElementById(`result-${testKey}-${testType}`);
        if (!card) {
            card = document.createElement('div');
            card.id = `result-${testKey}-${testType}`;
            card.className = 'result-card bg-white dark:bg-gray-800 rounded-lg shadow-lg p-4';
            liveResults.appendChild(card);
        }

        const speedText = result.error
            ? `<span class="text-red-500">Error: ${result.error}</span>`
            : `<span class="text-green-500 font-bold">${result.speed_mbps} Mbps</span>`;

        const badgeColor = testType === 'proxy'
            ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'
            : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200';

        card.innerHTML = `
                    <div class="flex justify-between items-center mb-2">
                        <h3 class="font-semibold text-gray-800 dark:text-white">${result.location}</h3>
                        <span class="text-xs px-2 py-1 rounded ${badgeColor}">
                            ${result.server_name}
                        </span>
                        </div>
                    <div class="text-2xl font-bold mb-1">
                        ${speedText}
                    </div>
                    ${!result.error ? `
                        <div class="text-sm text-gray-600 dark:text-gray-400">
                            ${(result.data_transferred / 1024 / 1024).toFixed(2)} MB in ${result.duration}s
                    </div>
                    ` : ''}
                `;
    }

    renderMetrics() {
        const proxyResults = Object.values(this.results.proxy).filter(r => !r.error);
        const directResults = Object.values(this.results.direct).filter(r => !r.error);

        // Find best proxy result
        const bestProxyResult = proxyResults.length > 0
            ? proxyResults.reduce((best, current) =>
                current.speed_mbps > best.speed_mbps ? current : best)
            : null;

        // Find best direct result
        const bestDirectResult = directResults.length > 0
            ? directResults.reduce((best, current) =>
                current.speed_mbps > best.speed_mbps ? current : best)
            : null;

        const bestProxySpeed = bestProxyResult ? bestProxyResult.speed_mbps : 0;
        const bestDirectSpeed = bestDirectResult ? bestDirectResult.speed_mbps : 0;

        // Calculate averages
        const avgProxySpeed = proxyResults.length > 0
            ? proxyResults.reduce((sum, r) => sum + r.speed_mbps, 0) / proxyResults.length
            : 0;

        // Speed difference based on best speeds (more relevant)
        const speedDifference = bestDirectSpeed > 0
            ? ((bestProxySpeed - bestDirectSpeed) / bestDirectSpeed * 100)
            : 0;

        // Update metrics
        document.getElementById('bestProxySpeed').textContent = `${bestProxySpeed.toFixed(2)} Mbps`;
        document.getElementById('bestDirectSpeed').textContent = `${bestDirectSpeed.toFixed(2)} Mbps`;
        document.getElementById('avgProxySpeed').textContent = `${avgProxySpeed.toFixed(2)} Mbps`;
        document.getElementById('speedDifference').textContent = `${speedDifference >= 0 ? '+' : ''}${speedDifference.toFixed(1)}%`;

        // Update additional info
        document.getElementById('bestProxyServer').textContent = bestProxyResult
            ? `${bestProxyResult.server_name} - ${bestProxyResult.location}`
            : '--';
        document.getElementById('bestDirectLocation').textContent = bestDirectResult
            ? bestDirectResult.location
            : '--';
        document.getElementById('proxyTestCount').textContent = `${proxyResults.length} tests`;

        // Update metric card colors based on performance
        const bestProxyMetric = document.getElementById('bestProxyMetric');
        const speedDiffMetric = document.getElementById('speedDiffMetric');

        // Reset classes
        bestProxyMetric.className = 'metric-card text-white p-4 rounded-lg text-center';
        speedDiffMetric.className = 'metric-card text-white p-4 rounded-lg text-center';

        if (bestProxySpeed >= bestDirectSpeed * 0.8) {
            bestProxyMetric.className += ' success';
        } else if (bestProxySpeed >= bestDirectSpeed * 0.5) {
            bestProxyMetric.className += ' warning';
        }

        if (speedDifference >= -20) {
            speedDiffMetric.className += ' success';
        } else {
            speedDiffMetric.className += ' warning';
        }

        // Render server comparison metrics
        this.renderServerMetrics();
    }

    renderServerMetrics() {
        const serverComparisonGrid = document.getElementById('serverComparisonGrid');
        const proxyResults = Object.values(this.results.proxy).filter(r => !r.error);

        // Group results by server
        const serverStats = {};
        proxyResults.forEach(result => {
            if (!serverStats[result.server_name]) {
                serverStats[result.server_name] = [];
            }
            serverStats[result.server_name].push(result);
        });

        const serverMetrics = Object.entries(serverStats).map(([serverName, results]) => {
            const speeds = results.map(r => r.speed_mbps);
            const avgSpeed = speeds.reduce((sum, speed) => sum + speed, 0) / speeds.length;
            const bestSpeed = Math.max(...speeds);
            const testCount = results.length;
            const bestLocation = results.find(r => r.speed_mbps === bestSpeed)?.location || '--';

            return {
                name: serverName,
                avgSpeed,
                bestSpeed,
                testCount,
                bestLocation
            };
        }).sort((a, b) => b.bestSpeed - a.bestSpeed);

        serverComparisonGrid.innerHTML = serverMetrics.map((server, index) => {
            const rankClass = index === 0 ? 'border-green-500 bg-green-50 dark:bg-green-900/20' :
                index === 1 ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' :
                    'border-gray-300 dark:border-gray-600';

            const rankIcon = index === 0 ? '🥇' : index === 1 ? '🥈' : index === 2 ? '🥉' : `#${index + 1}`;

            return `
                        <div class="border-2 ${rankClass} rounded-lg p-4">
                            <div class="flex items-center justify-between mb-2">
                                <h4 class="font-semibold text-gray-800 dark:text-white">${server.name}</h4>
                                <span class="text-lg">${rankIcon}</span>
                    </div>
                            <div class="space-y-1 text-sm">
                                <div class="flex justify-between">
                                    <span class="text-gray-600 dark:text-gray-400">Best Speed:</span>
                                    <span class="font-bold text-green-600 dark:text-green-400">${server.bestSpeed.toFixed(2)} Mbps</span>
                    </div>
                                <div class="flex justify-between">
                                    <span class="text-gray-600 dark:text-gray-400">Avg Speed:</span>
                                    <span class="font-medium">${server.avgSpeed.toFixed(2)} Mbps</span>
                </div>
                                <div class="flex justify-between">
                                    <span class="text-gray-600 dark:text-gray-400">Best Location:</span>
                                    <span class="font-medium">${server.bestLocation}</span>
                </div>
                                <div class="flex justify-between">
                                    <span class="text-gray-600 dark:text-gray-400">Tests:</span>
                                    <span>${server.testCount}</span>
            </div>
                            </div>
                        </div>
                    `;
        }).join('');

        if (serverMetrics.length === 0) {
            serverComparisonGrid.innerHTML = `
                        <div class="col-span-full text-center text-gray-500 dark:text-gray-400 py-8">
                            No proxy test results available
                    </div>
                    `;
        }
    }

    renderCharts() {
        const isDark = html.classList.contains('dark');
        const textColor = isDark ? '#e5e7eb' : '#374151';
        const gridColor = isDark ? '#374151' : '#e5e7eb';

        // Add a small delay to ensure DOM is ready
        setTimeout(() => {
            // Speed Comparison Chart
            this.renderSpeedChart(textColor, gridColor);

            // Server Performance Chart
            this.renderServerChart(textColor, gridColor);
        }, 100);
    }

    setupResizeHandler() {
        let resizeTimeout;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(() => {
                if (document.getElementById('resultsView').classList.contains('hidden')) {
                    return; // Don't resize if results view is not visible
                }
                this.renderCharts();
            }, 250);
        });
    }

    renderSpeedChart(textColor, gridColor) {
        const canvas = document.getElementById('speedChart');
        const ctx = canvas.getContext('2d');

        if (this.charts.speedChart) {
            this.charts.speedChart.destroy();
        }

        // Ensure proper canvas sizing
        const container = canvas.parentElement;
        const containerRect = container.getBoundingClientRect();
        canvas.style.width = '100%';
        canvas.style.height = '100%';

        const locations = [...new Set([
            ...Object.values(this.results.proxy).map(r => r.location),
            ...Object.values(this.results.direct).map(r => r.location)
        ])].filter(Boolean);

        if (locations.length === 0) {
            return;
        }

        // Group proxy results by server and location
        const serverNames = [...new Set(Object.values(this.results.proxy).map(r => r.server_name))];

        // Create datasets for each server + direct
        const datasets = [];

        // Color palette for different servers
        const colors = [
            {bg: 'rgba(59, 130, 246, 0.8)', border: 'rgba(59, 130, 246, 1)'}, // Blue
            {bg: 'rgba(16, 185, 129, 0.8)', border: 'rgba(16, 185, 129, 1)'}, // Green
            {bg: 'rgba(245, 158, 11, 0.8)', border: 'rgba(245, 158, 11, 1)'}, // Yellow
            {bg: 'rgba(239, 68, 68, 0.8)', border: 'rgba(239, 68, 68, 1)'}, // Red
            {bg: 'rgba(168, 85, 247, 0.8)', border: 'rgba(168, 85, 247, 1)'}, // Purple
        ];

        // Add datasets for each server
        serverNames.forEach((serverName, index) => {
            const color = colors[index % colors.length];
            const data = locations.map(location => {
                const result = Object.values(this.results.proxy).find(r =>
                    r.location === location && r.server_name === serverName && !r.error
                );
                return result ? result.speed_mbps : 0;
            });

            datasets.push({
                label: `${serverName} (Proxy)`,
                data: data,
                backgroundColor: color.bg,
                borderColor: color.border,
                borderWidth: 1
            });
        });

        // Add direct speed dataset
        const directData = locations.map(location => {
            const result = this.results.direct[location];
            return result && !result.error ? result.speed_mbps : 0;
        });

        datasets.push({
            label: 'Direct Connection',
            data: directData,
            backgroundColor: 'rgba(107, 114, 128, 0.8)',
            borderColor: 'rgba(107, 114, 128, 1)',
            borderWidth: 1
        });

        this.charts.speedChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: locations,
                datasets: datasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    intersect: false,
                },
                plugins: {
                    legend: {
                        labels: {
                            color: textColor,
                            usePointStyle: true,
                            padding: 15,
                            font: {
                                size: 12
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Speed (Mbps)',
                            color: textColor
                        },
                        ticks: {
                            color: textColor,
                            maxTicksLimit: 8
                        },
                        grid: {
                            color: gridColor
                        }
                    },
                    x: {
                        ticks: {
                            color: textColor,
                            maxRotation: 45
                        },
                        grid: {
                            color: gridColor
                        }
                    }
                }
            }
        });
    }

    renderServerChart(textColor, gridColor) {
        const canvas = document.getElementById('serverChart');
        const ctx = canvas.getContext('2d');

        if (!ctx) {
            console.error('Failed to get canvas context');
            return;
        }

        if (this.charts.serverChart) {
            this.charts.serverChart.destroy();
        }

        // Ensure proper canvas sizing
        const container = canvas.parentElement;
        const containerRect = container.getBoundingClientRect();
        canvas.style.width = '100%';
        canvas.style.height = '100%';

        // Group results by server
        const serverStats = {};

        Object.values(this.results.proxy).forEach(result => {
            if (!result.error && result.server_name) {
                if (!serverStats[result.server_name]) {
                    serverStats[result.server_name] = [];
                }
                serverStats[result.server_name].push(result.speed_mbps);
            }
        });

        const serverNames = Object.keys(serverStats);

        if (serverNames.length === 0) {
            // Show a message for no data
            ctx.fillStyle = textColor;
            ctx.font = '16px Arial';
            ctx.textAlign = 'center';
            ctx.fillText('No server data available', canvas.width / 2, canvas.height / 2);
            return;
        }

        // Use a bar chart instead of radar for better clarity
        const avgSpeeds = serverNames.map(name => {
            const speeds = serverStats[name];
            return speeds.reduce((sum, speed) => sum + speed, 0) / speeds.length;
        });
        const maxSpeeds = serverNames.map(name => Math.max(...serverStats[name]));
        const minSpeeds = serverNames.map(name => Math.min(...serverStats[name]));

        this.charts.serverChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: serverNames,
                datasets: [
                    {
                        label: 'Best Speed',
                        data: maxSpeeds,
                        backgroundColor: 'rgba(34, 197, 94, 0.8)',
                        borderColor: 'rgba(34, 197, 94, 1)',
                        borderWidth: 1,
                        order: 1
                    },
                    {
                        label: 'Average Speed',
                        data: avgSpeeds,
                        backgroundColor: 'rgba(59, 130, 246, 0.8)',
                        borderColor: 'rgba(59, 130, 246, 1)',
                        borderWidth: 1,
                        order: 2
                    },
                    {
                        label: 'Worst Speed',
                        data: minSpeeds,
                        backgroundColor: 'rgba(239, 68, 68, 0.8)',
                        borderColor: 'rgba(239, 68, 68, 1)',
                        borderWidth: 1,
                        order: 3
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    intersect: false,
                },
                plugins: {
                    legend: {
                        labels: {
                            color: textColor,
                            usePointStyle: true,
                            padding: 15,
                            font: {
                                size: 12
                            }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            afterLabel: function (context) {
                                const serverName = context.label;
                                const speeds = serverStats[serverName];
                                return `Tests: ${speeds.length}`;
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Speed (Mbps)',
                            color: textColor
                        },
                        ticks: {
                            color: textColor,
                            maxTicksLimit: 8
                        },
                        grid: {
                            color: gridColor
                        }
                    },
                    x: {
                        ticks: {
                            color: textColor,
                            maxRotation: 45
                        },
                        grid: {
                            color: gridColor
                        }
                    }
                }
            }
        });
    }

    renderDetailedResults() {
        const detailedResults = document.getElementById('detailedResults');
        const locations = [...new Set([
            ...Object.values(this.results.proxy).map(r => r.location),
            ...Object.values(this.results.direct).map(r => r.location)
        ])].filter(Boolean);

        detailedResults.innerHTML = locations.map(location => {
            const proxyResults = Object.values(this.results.proxy).filter(r => r.location === location);
            const directResult = this.results.direct[location];

            return `
                        <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                            <h3 class="font-semibold text-lg text-gray-800 dark:text-white mb-3">${location}</h3>
                            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                ${proxyResults.map(result => `
                                    <div class="space-y-2">
                                        <div class="flex items-center space-x-2">
                                            <span class="text-xs px-2 py-1 bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 rounded">${result.server_name}</span>
                                        </div>
                                        ${result.error ? `
                                            <div class="text-red-500">Error: ${result.error}</div>
                                        ` : `
                                            <div class="text-xl font-bold text-blue-600 dark:text-blue-400">${result.speed_mbps} Mbps</div>
                                            <div class="text-sm text-gray-600 dark:text-gray-400">
                                                ${(result.data_transferred / 1024 / 1024).toFixed(2)} MB in ${result.duration}s
                                            </div>
                                        `}
                                    </div>
                                `).join('')}

                                ${directResult ? `
                                    <div class="space-y-2">
                                        <div class="flex items-center space-x-2">
                                            <span class="text-xs px-2 py-1 bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200 rounded">Direct</span>
                                        </div>
                                        ${directResult.error ? `
                                            <div class="text-red-500">Error: ${directResult.error}</div>
                                        ` : `
                                            <div class="text-xl font-bold text-gray-600 dark:text-gray-400">${directResult.speed_mbps} Mbps</div>
                                            <div class="text-sm text-gray-600 dark:text-gray-400">
                                                ${(directResult.data_transferred / 1024 / 1024).toFixed(2)} MB in ${directResult.duration}s
                                            </div>
                                        `}
                                    </div>
                                ` : '<div class="text-gray-400">Direct test not performed</div>'}
                            </div>
                        </div>
                    `;
        }).join('');
    }
}


// Initialize the speed test when the page loads
let speedTest;
document.addEventListener('DOMContentLoaded', () => {
    speedTest = new MediaFlowSpeedTest();
});