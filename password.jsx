import React, { useState, useEffect } from 'react';
import { Eye, EyeOff, Shield, AlertTriangle, CheckCircle, XCircle, Info, RefreshCw, Copy, Zap, TrendingUp, Clock, Users } from 'lucide-react';

const PasswordStrengthAnalyzer = () => {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  const [generatedPassword, setGeneratedPassword] = useState('');
  const [generatorOptions, setGeneratorOptions] = useState({
    length: 16,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
    excludeSimilar: true
  });
  const [showGenerator, setShowGenerator] = useState(false);
  const [passwordHistory, setPasswordHistory] = useState([]);
  const [activeTab, setActiveTab] = useState('analyzer');
  const [copySuccess, setCopySuccess] = useState('');

  // Common passwords list (expanded)
  const commonPasswords = new Set([
    'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
    'admin', 'letmein', 'welcome', 'monkey', '1234567890', 'password1',
    'qwerty123', 'dragon', 'master', 'hello', 'freedom', 'whatever',
    'login', 'princess', 'solo', 'qwertyuiop', 'starwars', 'superman',
    'michael', 'jennifer', 'jordan', 'michelle', 'daniel', 'andrew',
    'joshua', 'matthew', 'anthony', 'mark', 'donald', 'steven'
  ]);

  // Common patterns to check
  const commonPatterns = [
    { pattern: /(.)\1{2,}/, name: 'Repeated characters', severity: 'medium' },
    { pattern: /123|234|345|456|567|678|789|890/, name: 'Sequential numbers', severity: 'medium' },
    { pattern: /abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i, name: 'Sequential letters', severity: 'medium' },
    { pattern: /qwerty|asdf|zxcv/i, name: 'Keyboard patterns', severity: 'high' },
    { pattern: /password|pass|pwd/i, name: 'Contains "password"', severity: 'high' },
    { pattern: /\d{4}/, name: 'Year patterns', severity: 'medium' },
    { pattern: /(love|hate|like|admin|user)/i, name: 'Common words', severity: 'medium' }
  ];

  const generatePassword = () => {
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    const similar = 'il1Lo0O';

    let charset = '';
    if (generatorOptions.lowercase) charset += lowercase;
    if (generatorOptions.uppercase) charset += uppercase;
    if (generatorOptions.numbers) charset += numbers;
    if (generatorOptions.symbols) charset += symbols;

    if (generatorOptions.excludeSimilar) {
      charset = charset.split('').filter(char => !similar.includes(char)).join('');
    }

    let result = '';
    for (let i = 0; i < generatorOptions.length; i++) {
      result += charset.charAt(Math.floor(Math.random() * charset.length));
    }

    setGeneratedPassword(result);
    return result;
  };

  const copyToClipboard = async (text, type = 'password') => {
    try {
      await navigator.clipboard.writeText(text);
      setCopySuccess(`${type} copied!`);
      setTimeout(() => setCopySuccess(''), 2000);
    } catch (err) {
      setCopySuccess('Failed to copy');
      setTimeout(() => setCopySuccess(''), 2000);
    }
  };

  const useGeneratedPassword = () => {
    if (generatedPassword) {
      setPassword(generatedPassword);
      setActiveTab('analyzer');
    }
  };

  const analyzePassword = (pwd) => {
    if (!pwd) return null;

    const checks = {
      length: pwd.length >= 12,
      minLength: pwd.length >= 8,
      uppercase: /[A-Z]/.test(pwd),
      lowercase: /[a-z]/.test(pwd),
      numbers: /\d/.test(pwd),
      symbols: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>?]/.test(pwd),
      noSpaces: !/\s/.test(pwd),
      notCommon: !commonPasswords.has(pwd.toLowerCase()),
      noPersonalInfo: !/\b(name|birth|date|year|123|abc)\b/i.test(pwd)
    };

    // Pattern analysis
    const detectedPatterns = commonPatterns.filter(p => p.pattern.test(pwd));

    // Calculate entropy (approximate)
    let charsetSize = 0;
    if (/[a-z]/.test(pwd)) charsetSize += 26;
    if (/[A-Z]/.test(pwd)) charsetSize += 26;
    if (/\d/.test(pwd)) charsetSize += 10;
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>?]/.test(pwd)) charsetSize += 32;
    
    const entropy = pwd.length * Math.log2(charsetSize);
    
    // Calculate score
    let score = 0;
    if (checks.length) score += 25;
    else if (checks.minLength) score += 10;
    
    if (checks.uppercase) score += 15;
    if (checks.lowercase) score += 15;
    if (checks.numbers) score += 15;
    if (checks.symbols) score += 20;
    if (checks.notCommon) score += 10;
    
    // Deduct points for patterns
    score -= detectedPatterns.length * 10;
    
    // Bonus for very long passwords
    if (pwd.length > 16) score += 10;
    if (pwd.length > 20) score += 10;

    score = Math.max(0, Math.min(100, score));

    // Determine strength level
    let strength = 'Very Weak';
    let color = 'text-red-400';
    let bgColor = 'bg-red-900/20';
    let borderColor = 'border-red-500/50';
    let icon = XCircle;

    if (score >= 80) {
      strength = 'Very Strong';
      color = 'text-green-400';
      bgColor = 'bg-green-900/20';
      borderColor = 'border-green-500/50';
      icon = CheckCircle;
    } else if (score >= 60) {
      strength = 'Strong';
      color = 'text-blue-400';
      bgColor = 'bg-blue-900/20';
      borderColor = 'border-blue-500/50';
      icon = Shield;
    } else if (score >= 40) {
      strength = 'Moderate';
      color = 'text-yellow-400';
      bgColor = 'bg-yellow-900/20';
      borderColor = 'border-yellow-500/50';
      icon = AlertTriangle;
    } else if (score >= 20) {
      strength = 'Weak';
      color = 'text-orange-400';
      bgColor = 'bg-orange-900/20';
      borderColor = 'border-orange-500/50';
      icon = AlertTriangle;
    }

    // Time to crack estimation (simplified)
    const attemptsPerSecond = 1000000000; // 1 billion attempts per second
    const possibleCombinations = Math.pow(charsetSize, pwd.length);
    const secondsToCrack = possibleCombinations / (2 * attemptsPerSecond);
    
    let timeToCrack = 'Less than a second';
    if (secondsToCrack > 31536000 * 1000000) { // 1 million years
      timeToCrack = `${Math.round(secondsToCrack / (31536000 * 1000000))}M years`;
    } else if (secondsToCrack > 31536000 * 1000) { // 1 thousand years
      timeToCrack = `${Math.round(secondsToCrack / (31536000 * 1000))}K years`;
    } else if (secondsToCrack > 31536000) { // 1 year
      timeToCrack = `${Math.round(secondsToCrack / 31536000)} years`;
    } else if (secondsToCrack > 86400) { // 1 day
      timeToCrack = `${Math.round(secondsToCrack / 86400)} days`;
    } else if (secondsToCrack > 3600) { // 1 hour
      timeToCrack = `${Math.round(secondsToCrack / 3600)} hours`;
    } else if (secondsToCrack > 60) { // 1 minute
      timeToCrack = `${Math.round(secondsToCrack / 60)} minutes`;
    } else if (secondsToCrack > 1) {
      timeToCrack = `${Math.round(secondsToCrack)} seconds`;
    }

    return {
      score,
      strength,
      color,
      bgColor,
      borderColor,
      icon,
      entropy: Math.round(entropy),
      timeToCrack,
      checks,
      detectedPatterns,
      suggestions: generateSuggestions(checks, detectedPatterns, pwd)
    };
  };

  const generateSuggestions = (checks, patterns, pwd) => {
    const suggestions = [];

    if (!checks.minLength) {
      suggestions.push({ type: 'critical', text: 'Use at least 8 characters (12+ recommended)' });
    } else if (!checks.length) {
      suggestions.push({ type: 'important', text: 'Use at least 12 characters for better security' });
    }

    if (!checks.uppercase) {
      suggestions.push({ type: 'important', text: 'Add uppercase letters (A-Z)' });
    }

    if (!checks.lowercase) {
      suggestions.push({ type: 'important', text: 'Add lowercase letters (a-z)' });
    }

    if (!checks.numbers) {
      suggestions.push({ type: 'important', text: 'Add numbers (0-9)' });
    }

    if (!checks.symbols) {
      suggestions.push({ type: 'important', text: 'Add special characters (!@#$%^&*)' });
    }

    if (!checks.notCommon) {
      suggestions.push({ type: 'critical', text: 'Avoid common passwords' });
    }

    patterns.forEach(pattern => {
      if (pattern.severity === 'high') {
        suggestions.push({ type: 'critical', text: `Avoid ${pattern.name.toLowerCase()}` });
      } else {
        suggestions.push({ type: 'warning', text: `Minimize ${pattern.name.toLowerCase()}` });
      }
    });

    if (pwd.length > 0 && suggestions.length === 0) {
      suggestions.push({ type: 'success', text: 'Excellent! Consider using a password manager.' });
    }

    return suggestions;
  };

  const addToHistory = (pwd, analysis) => {
    if (pwd && analysis) {
      const historyItem = {
        id: Date.now(),
        password: pwd.substring(0, 20) + (pwd.length > 20 ? '...' : ''),
        score: analysis.score,
        strength: analysis.strength,
        timestamp: new Date().toLocaleTimeString()
      };
      setPasswordHistory(prev => [historyItem, ...prev.slice(0, 4)]);
    }
  };

  useEffect(() => {
    const newAnalysis = analyzePassword(password);
    setAnalysis(newAnalysis);
    
    if (password && newAnalysis) {
      const timeoutId = setTimeout(() => {
        addToHistory(password, newAnalysis);
      }, 1000);
      return () => clearTimeout(timeoutId);
    }
  }, [password]);

  const getSuggestionIcon = (type) => {
    switch (type) {
      case 'critical': return <XCircle className="w-4 h-4 text-red-400" />;
      case 'important': return <AlertTriangle className="w-4 h-4 text-orange-400" />;
      case 'warning': return <Info className="w-4 h-4 text-yellow-400" />;
      case 'success': return <CheckCircle className="w-4 h-4 text-green-400" />;
      default: return <Info className="w-4 h-4 text-gray-400" />;
    }
  };

  const StatCard = ({ icon: Icon, label, value, color = "text-blue-400" }) => (
    <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700/50 rounded-lg p-4">
      <div className="flex items-center space-x-3">
        <Icon className={`w-6 h-6 ${color}`} />
        <div>
          <p className="text-gray-300 text-sm">{label}</p>
          <p className={`font-bold text-lg ${color}`}>{value}</p>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 text-white">
      <div className="max-w-6xl mx-auto p-6">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold mb-2 bg-gradient-to-r from-yellow-400 to-orange-500 bg-clip-text text-transparent">
            Password Security Suite
          </h1>
          <p className="text-gray-400">Advanced password analysis and generation tools</p>
        </div>

        {/* Navigation Tabs */}
        <div className="flex justify-center mb-8">
          <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg p-1 border border-gray-700/50">
            <button
              onClick={() => setActiveTab('analyzer')}
              className={`px-6 py-2 rounded-md transition-all ${
                activeTab === 'analyzer'
                  ? 'bg-yellow-500 text-gray-900 font-medium'
                  : 'text-gray-300 hover:text-white'
              }`}
            >
              <Shield className="w-4 h-4 inline mr-2" />
              Analyzer
            </button>
            <button
              onClick={() => setActiveTab('generator')}
              className={`px-6 py-2 rounded-md transition-all ${
                activeTab === 'generator'
                  ? 'bg-yellow-500 text-gray-900 font-medium'
                  : 'text-gray-300 hover:text-white'
              }`}
            >
              <Zap className="w-4 h-4 inline mr-2" />
              Generator
            </button>
          </div>
        </div>

        {copySuccess && (
          <div className="fixed top-4 right-4 bg-green-600 text-white px-4 py-2 rounded-lg shadow-lg z-50">
            {copySuccess}
          </div>
        )}

        {activeTab === 'analyzer' && (
          <div className="space-y-6">
            {/* Password Input */}
            <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700/50 rounded-lg p-6">
              <label className="block text-sm font-medium text-gray-300 mb-3">
                Enter Password to Analyze
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-4 py-3 bg-gray-900/50 border border-gray-600 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-transparent text-white placeholder-gray-400 pr-20"
                  placeholder="Type your password here..."
                />
                <div className="absolute right-3 top-1/2 transform -translate-y-1/2 flex space-x-2">
                  <button
                    onClick={() => copyToClipboard(password)}
                    className="text-gray-400 hover:text-yellow-400 transition-colors"
                    disabled={!password}
                  >
                    <Copy className="w-5 h-5" />
                  </button>
                  <button
                    onClick={() => setShowPassword(!showPassword)}
                    className="text-gray-400 hover:text-yellow-400 transition-colors"
                  >
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>
            </div>

            {analysis && (
              <div className="space-y-6">
                {/* Strength Overview */}
                <div className={`p-6 rounded-lg border ${analysis.bgColor} ${analysis.borderColor}`}>
                  <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center space-x-4">
                      <analysis.icon className={`w-10 h-10 ${analysis.color}`} />
                      <div>
                        <h2 className={`text-3xl font-bold ${analysis.color}`}>{analysis.strength}</h2>
                        <p className="text-gray-400">Password Strength</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className={`text-4xl font-bold ${analysis.color}`}>{analysis.score}/100</div>
                      <p className="text-sm text-gray-400">Security Score</p>
                    </div>
                  </div>
                  
                  {/* Progress Bar */}
                  <div className="w-full bg-gray-700 rounded-full h-4 mb-4">
                    <div 
                      className={`h-4 rounded-full transition-all duration-500 ${
                        analysis.score >= 80 ? 'bg-gradient-to-r from-green-500 to-green-400' :
                        analysis.score >= 60 ? 'bg-gradient-to-r from-blue-500 to-blue-400' :
                        analysis.score >= 40 ? 'bg-gradient-to-r from-yellow-500 to-yellow-400' :
                        analysis.score >= 20 ? 'bg-gradient-to-r from-orange-500 to-orange-400' : 
                        'bg-gradient-to-r from-red-500 to-red-400'
                      }`}
                      style={{ width: `${analysis.score}%` }}
                    ></div>
                  </div>

                  {/* Quick Stats */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <StatCard
                      icon={TrendingUp}
                      label="Entropy"
                      value={`${analysis.entropy} bits`}
                      color="text-purple-400"
                    />
                    <StatCard
                      icon={Clock}
                      label="Crack Time"
                      value={analysis.timeToCrack}
                      color="text-green-400"
                    />
                    <StatCard
                      icon={Users}
                      label="Length"
                      value={`${password.length} chars`}
                      color="text-blue-400"
                    />
                    <StatCard
                      icon={Shield}
                      label="Patterns"
                      value={analysis.detectedPatterns.length === 0 ? 'Clean' : `${analysis.detectedPatterns.length} found`}
                      color={analysis.detectedPatterns.length === 0 ? 'text-green-400' : 'text-red-400'}
                    />
                  </div>
                </div>

                {/* Requirements Grid */}
                <div className="grid md:grid-cols-2 gap-6">
                  <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700/50 rounded-lg p-6">
                    <h3 className="text-xl font-semibold mb-4 text-yellow-400">Security Requirements</h3>
                    <div className="space-y-3">
                      {[
                        { key: 'minLength', label: 'At least 8 characters', required: true },
                        { key: 'length', label: '12+ characters (recommended)', required: false },
                        { key: 'uppercase', label: 'Uppercase letters (A-Z)', required: true },
                        { key: 'lowercase', label: 'Lowercase letters (a-z)', required: true },
                        { key: 'numbers', label: 'Numbers (0-9)', required: true },
                        { key: 'symbols', label: 'Special characters (!@#$)', required: true },
                        { key: 'notCommon', label: 'Not a common password', required: true }
                      ].map(req => (
                        <div key={req.key} className="flex items-center justify-between">
                          <div className="flex items-center space-x-3">
                            {analysis.checks[req.key] ? (
                              <CheckCircle className="w-5 h-5 text-green-400" />
                            ) : (
                              <XCircle className="w-5 h-5 text-red-400" />
                            )}
                            <span className={`${analysis.checks[req.key] ? 'text-green-300' : 'text-red-300'}`}>
                              {req.label}
                            </span>
                          </div>
                          {req.required && (
                            <span className="text-xs px-2 py-1 bg-yellow-500/20 text-yellow-400 rounded">
                              Required
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Password History */}
                  <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700/50 rounded-lg p-6">
                    <h3 className="text-xl font-semibold mb-4 text-yellow-400">Recent Analysis</h3>
                    {passwordHistory.length > 0 ? (
                      <div className="space-y-3">
                        {passwordHistory.map(item => (
                          <div key={item.id} className="flex items-center justify-between p-3 bg-gray-900/50 rounded-lg">
                            <div>
                              <p className="text-gray-300 font-mono text-sm">{item.password}</p>
                              <p className="text-xs text-gray-500">{item.timestamp}</p>
                            </div>
                            <div className="text-right">
                              <p className="text-sm font-medium text-gray-300">{item.strength}</p>
                              <p className="text-xs text-gray-400">{item.score}/100</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-gray-400 text-center py-8">No password history yet</p>
                    )}
                  </div>
                </div>

                {/* Detected Patterns */}
                {analysis.detectedPatterns.length > 0 && (
                  <div className="bg-red-900/20 border border-red-500/50 rounded-lg p-6">
                    <h3 className="text-xl font-semibold text-red-400 mb-4">Security Issues Detected</h3>
                    <div className="grid md:grid-cols-2 gap-4">
                      {analysis.detectedPatterns.map((pattern, index) => (
                        <div key={index} className="flex items-center space-x-3 p-3 bg-red-900/30 rounded-lg">
                          <AlertTriangle className="w-5 h-5 text-red-400" />
                          <div className="flex-1">
                            <span className="text-red-200">{pattern.name}</span>
                            <span className={`ml-2 px-2 py-1 rounded text-xs ${
                              pattern.severity === 'high' ? 'bg-red-600/30 text-red-300' : 'bg-yellow-600/30 text-yellow-300'
                            }`}>
                              {pattern.severity}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Suggestions */}
                <div className="bg-blue-900/20 border border-blue-500/50 rounded-lg p-6">
                  <h3 className="text-xl font-semibold text-blue-400 mb-4">Improvement Suggestions</h3>
                  <div className="grid md:grid-cols-2 gap-4">
                    {analysis.suggestions.map((suggestion, index) => (
                      <div key={index} className="flex items-start space-x-3 p-3 bg-blue-900/30 rounded-lg">
                        {getSuggestionIcon(suggestion.type)}
                        <span className="text-gray-200">{suggestion.text}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {!password && (
              <div className="text-center py-16 text-gray-400">
                <Shield className="w-20 h-20 mx-auto mb-6 text-gray-600" />
                <h3 className="text-xl font-medium mb-2">Ready to Analyze</h3>
                <p>Enter a password above to see detailed security analysis</p>
              </div>
            )}
          </div>
        )}

        {activeTab === 'generator' && (
          <div className="space-y-6">
            {/* Generator Options */}
            <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700/50 rounded-lg p-6">
              <h3 className="text-xl font-semibold text-yellow-400 mb-6">Password Generator</h3>
              
              <div className="grid md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-3">
                    Password Length: {generatorOptions.length}
                  </label>
                  <input
                    type="range"
                    min="8"
                    max="64"
                    value={generatorOptions.length}
                    onChange={(e) => setGeneratorOptions({...generatorOptions, length: parseInt(e.target.value)})}
                    className="w-full h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer slider"
                  />
                  <div className="flex justify-between text-xs text-gray-400 mt-1">
                    <span>8</span>
                    <span>64</span>
                  </div>
                </div>

                <div className="space-y-4">
                  <h4 className="text-sm font-medium text-gray-300">Character Types</h4>
                  {[
                    { key: 'uppercase', label: 'Uppercase (A-Z)' },
                    { key: 'lowercase', label: 'Lowercase (a-z)' },
                    { key: 'numbers', label: 'Numbers (0-9)' },
                    { key: 'symbols', label: 'Symbols (!@#$)' },
                    { key: 'excludeSimilar', label: 'Exclude similar chars (il1Lo0O)' }
                  ].map(option => (
                    <label key={option.key} className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        checked={generatorOptions[option.key]}
                        onChange={(e) => setGeneratorOptions({
                          ...generatorOptions,
                          [option.key]: e.target.checked
                        })}
                        className="w-4 h-4 text-yellow-500 bg-gray-700 border-gray-600 rounded focus:ring-yellow-500"
                      />
                      <span className="text-gray-300">{option.label}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="flex space-x-4 mt-6">
                <button
                  onClick={generatePassword}
                  className="flex-1 bg-gradient-to-r from-yellow-500 to-orange-500 text-gray-900 font-medium py-3 px-6 rounded-lg hover:from-yellow-400 hover:to-orange-400 transition-all flex items-center justify-center space-x-2"
                >
                  <RefreshCw className="w-5 h-5" />
                  <span>Generate Password</span>
                </button>
              </div>
            </div>

            {/* Generated Password Display */}
            {generatedPassword && (
              <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700/50 rounded-lg p-6">
                <h4 className="text-lg font-medium text-gray-300 mb-4">Generated Password</h4>
                <div className="bg-gray-900/50 border border-gray-600 rounded-lg p-4 mb-4">
                  <div className="flex items-center justify-between">
                    <code className="text-yellow-400 font-mono text-lg break-all">{generatedPassword}</code>
                    <button
                      onClick={() => copyToClipboard(generatedPassword, 'Generated password')}
                      className="text-gray-400 hover:text-yellow-400 transition-colors ml-4"
                    >
                      <Copy className="w-5 h-5" />
                    </button>
                  </div>
                </div>
                <div className="flex space-x-4">
                  <button
                    onClick={useGeneratedPassword}
                    className="flex-1 bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition-colors"
                  >
                    Use for Analysis
                  </button>
                  <button
                    onClick={generatePassword}
                    className="bg-gray-700 hover:bg-gray-600 text-white font-medium py-2 px-4 rounded-lg transition-colors flex items-center space-x-2"
                  >
                    <RefreshCw className="w-4 h-4" />
                    <span>Regenerate</span>
                  </button>
                </div>
              </div>
            )}

            {/* Password Strength Tips */}
            <div className="bg-green-900/20 border border-green-500/50 rounded-lg p-6">
              <h3 className="text-xl font-semibold text-green-400 mb-4">Password Security Tips</h3>
              <div className="grid md:grid-cols-2 gap-6">
                <div>
                  <h4 className="font-medium text-green-300 mb-3 flex items-center">
                    <CheckCircle className="w-5 h-5 mr-2" />
                    Best Practices
                  </h4>
                  <ul className="space-y-2 text-gray-300 text-sm">
                    <li>• Use unique passwords for each account</li>
                    <li>• Enable two-factor authentication when available</li>
                    <li>• Use a reputable password manager</li>
                    <li>• Consider passphrases with random words</li>
                    <li>• Update passwords regularly for sensitive accounts</li>
                    <li>• Never share passwords via email or text</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-medium text-red-300 mb-3 flex items-center">
                    <XCircle className="w-5 h-5 mr-2" />
                    Avoid These
                  </h4>
                  <ul className="space-y-2 text-gray-300 text-sm">
                    <li>• Personal information (birthdays, names)</li>
                    <li>• Dictionary words without modification</li>
                    <li>• Sequential patterns (123456, abcdef)</li>
                    <li>• Keyboard patterns (qwerty, asdf)</li>
                    <li>• Reusing passwords across multiple sites</li>
                    <li>• Storing passwords in plain text files</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Common Password Examples */}
            <div className="bg-orange-900/20 border border-orange-500/50 rounded-lg p-6">
              <h3 className="text-xl font-semibold text-orange-400 mb-4">Password Strength Examples</h3>
              <div className="space-y-4">
                {[
                  { password: 'password123', strength: 'Very Weak', color: 'text-red-400', reason: 'Common word + simple number' },
                  { password: 'P@ssw0rd!', strength: 'Weak', color: 'text-orange-400', reason: 'Predictable substitutions' },
                  { password: 'MyDog2023!', strength: 'Moderate', color: 'text-yellow-400', reason: 'Personal info + year' },
                  { password: 'Coffee#Morning$42', strength: 'Strong', color: 'text-blue-400', reason: 'Multiple words + symbols' },
                  { password: 'Tr0ub4dor&3', strength: 'Strong', color: 'text-blue-400', reason: 'XKCD style with modifications' },
                  { password: 'K7#mX9$pL2@vN5&qR8', strength: 'Very Strong', color: 'text-green-400', reason: 'Random characters, high entropy' }
                ].map((example, index) => (
                  <div key={index} className="flex items-center justify-between p-4 bg-gray-900/30 rounded-lg">
                    <div className="flex-1">
                      <code className="text-gray-300 font-mono">{example.password}</code>
                      <p className="text-xs text-gray-400 mt-1">{example.reason}</p>
                    </div>
                    <div className="text-right">
                      <span className={`font-medium ${example.color}`}>{example.strength}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="mt-12 text-center text-gray-500 text-sm">
          <p>🔒 All password analysis is performed locally in your browser. No data is transmitted or stored.</p>
        </div>
      </div>

      <style jsx>{`
        .slider::-webkit-slider-thumb {
          appearance: none;
          height: 20px;
          width: 20px;
          border-radius: 50%;
          background: #eab308;
          cursor: pointer;
        }
        
        .slider::-moz-range-thumb {
          height: 20px;
          width: 20px;
          border-radius: 50%;
          background: #eab308;
          cursor: pointer;
          border: none;
        }
      `}</style>
    </div>
  );
};

export default PasswordStrengthAnalyzer;