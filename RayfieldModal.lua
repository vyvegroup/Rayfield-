--[[
	
	Rayfield Modal Library
	Extension for Rayfield Interface Suite
	
	Features:
	- Modal Notifications (center screen)
	- Console/Code Display
	- Yes/No Confirmation Dialogs
	- Custom Prompts with Input
	
	Usage:
	local RayfieldModal = loadstring(game:HttpGet("YOUR_URL"))()
	
	-- Modal Notification
	RayfieldModal:Notify({
		Title = "Title",
		Content = "Content here",
		Duration = 5,
		Image = "check" -- or use rbxassetid://
	})
	
	-- Console/Code Display
	RayfieldModal:Console({
		Title = "Console",
		Content = "print('Hello World')",
		Language = "lua" -- optional
	})
	
	-- Yes/No Dialog
	RayfieldModal:Confirm({
		Title = "Confirm Action",
		Content = "Are you sure?",
		YesText = "Yes",
		NoText = "No",
		Callback = function(result)
			if result then
				print("User clicked Yes")
			else
				print("User clicked No")
			end
		end
	})
	
	-- Input Prompt
	RayfieldModal:Prompt({
		Title = "Enter Name",
		Placeholder = "Your name...",
		Default = "",
		Callback = function(text)
			print("User entered:", text)
		end
	})

]]--

-- Services
local TweenService = game:GetService("TweenService")
local UserInputService = game:GetService("UserInputService")
local CoreGui = game:GetService("CoreGui")
local RunService = game:GetService("RunService")

-- Rayfield Modal Library
local RayfieldModalLibrary = {
	Theme = {
		Default = {
			TextColor = Color3.fromRGB(240, 240, 240),
			Background = Color3.fromRGB(25, 25, 25),
			Topbar = Color3.fromRGB(34, 34, 34),
			Shadow = Color3.fromRGB(20, 20, 20),
			ElementBackground = Color3.fromRGB(35, 35, 35),
			ElementStroke = Color3.fromRGB(50, 50, 50),
			Accent = Color3.fromRGB(0, 146, 214),
			AccentHover = Color3.fromRGB(0, 170, 255),
			Success = Color3.fromRGB(46, 204, 113),
			Error = Color3.fromRGB(231, 76, 60),
			Warning = Color3.fromRGB(241, 196, 15),
			SecondaryBackground = Color3.fromRGB(30, 30, 30),
			InputBackground = Color3.fromRGB(30, 30, 30),
			InputStroke = Color3.fromRGB(65, 65, 65),
			PlaceholderColor = Color3.fromRGB(178, 178, 178),
			ConsoleBackground = Color3.fromRGB(18, 18, 18),
			ConsoleText = Color3.fromRGB(230, 230, 230),
		},
		Ocean = {
			TextColor = Color3.fromRGB(230, 240, 240),
			Background = Color3.fromRGB(20, 30, 30),
			Topbar = Color3.fromRGB(25, 40, 40),
			Shadow = Color3.fromRGB(15, 20, 20),
			ElementBackground = Color3.fromRGB(30, 50, 50),
			ElementStroke = Color3.fromRGB(45, 70, 70),
			Accent = Color3.fromRGB(0, 130, 130),
			AccentHover = Color3.fromRGB(0, 160, 160),
			Success = Color3.fromRGB(26, 188, 156),
			Error = Color3.fromRGB(192, 57, 43),
			Warning = Color3.fromRGB(243, 156, 18),
			SecondaryBackground = Color3.fromRGB(25, 40, 40),
			InputBackground = Color3.fromRGB(30, 50, 50),
			InputStroke = Color3.fromRGB(50, 70, 70),
			PlaceholderColor = Color3.fromRGB(140, 160, 160),
			ConsoleBackground = Color3.fromRGB(15, 25, 25),
			ConsoleText = Color3.fromRGB(220, 235, 235),
		},
		AmberGlow = {
			TextColor = Color3.fromRGB(255, 245, 230),
			Background = Color3.fromRGB(45, 30, 20),
			Topbar = Color3.fromRGB(55, 40, 25),
			Shadow = Color3.fromRGB(35, 25, 15),
			ElementBackground = Color3.fromRGB(60, 45, 35),
			ElementStroke = Color3.fromRGB(85, 60, 45),
			Accent = Color3.fromRGB(240, 130, 30),
			AccentHover = Color3.fromRGB(255, 160, 50),
			Success = Color3.fromRGB(46, 204, 113),
			Error = Color3.fromRGB(231, 76, 60),
			Warning = Color3.fromRGB(241, 196, 15),
			SecondaryBackground = Color3.fromRGB(50, 35, 25),
			InputBackground = Color3.fromRGB(60, 45, 35),
			InputStroke = Color3.fromRGB(90, 65, 50),
			PlaceholderColor = Color3.fromRGB(190, 150, 130),
			ConsoleBackground = Color3.fromRGB(35, 22, 15),
			ConsoleText = Color3.fromRGB(250, 230, 210),
		},
		Light = {
			TextColor = Color3.fromRGB(40, 40, 40),
			Background = Color3.fromRGB(245, 245, 245),
			Topbar = Color3.fromRGB(230, 230, 230),
			Shadow = Color3.fromRGB(200, 200, 200),
			ElementBackground = Color3.fromRGB(240, 240, 240),
			ElementStroke = Color3.fromRGB(210, 210, 210),
			Accent = Color3.fromRGB(0, 146, 214),
			AccentHover = Color3.fromRGB(0, 170, 255),
			Success = Color3.fromRGB(46, 204, 113),
			Error = Color3.fromRGB(231, 76, 60),
			Warning = Color3.fromRGB(241, 196, 15),
			SecondaryBackground = Color3.fromRGB(235, 235, 235),
			InputBackground = Color3.fromRGB(240, 240, 240),
			InputStroke = Color3.fromRGB(180, 180, 180),
			PlaceholderColor = Color3.fromRGB(140, 140, 140),
			ConsoleBackground = Color3.fromRGB(230, 230, 230),
			ConsoleText = Color3.fromRGB(30, 30, 30),
		},
		Amethyst = {
			TextColor = Color3.fromRGB(240, 240, 240),
			Background = Color3.fromRGB(30, 20, 40),
			Topbar = Color3.fromRGB(40, 25, 50),
			Shadow = Color3.fromRGB(20, 15, 30),
			ElementBackground = Color3.fromRGB(45, 30, 60),
			ElementStroke = Color3.fromRGB(70, 50, 85),
			Accent = Color3.fromRGB(120, 60, 150),
			AccentHover = Color3.fromRGB(140, 80, 170),
			Success = Color3.fromRGB(155, 89, 182),
			Error = Color3.fromRGB(192, 57, 43),
			Warning = Color3.fromRGB(243, 156, 18),
			SecondaryBackground = Color3.fromRGB(35, 22, 45),
			InputBackground = Color3.fromRGB(45, 30, 60),
			InputStroke = Color3.fromRGB(80, 50, 110),
			PlaceholderColor = Color3.fromRGB(178, 150, 200),
			ConsoleBackground = Color3.fromRGB(22, 15, 30),
			ConsoleText = Color3.fromRGB(230, 220, 240),
		},
		DarkBlue = {
			TextColor = Color3.fromRGB(230, 230, 230),
			Background = Color3.fromRGB(20, 25, 30),
			Topbar = Color3.fromRGB(30, 35, 40),
			Shadow = Color3.fromRGB(15, 20, 25),
			ElementBackground = Color3.fromRGB(30, 35, 40),
			ElementStroke = Color3.fromRGB(45, 50, 60),
			Accent = Color3.fromRGB(0, 120, 210),
			AccentHover = Color3.fromRGB(0, 150, 240),
			Success = Color3.fromRGB(46, 204, 113),
			Error = Color3.fromRGB(231, 76, 60),
			Warning = Color3.fromRGB(241, 196, 15),
			SecondaryBackground = Color3.fromRGB(25, 30, 35),
			InputBackground = Color3.fromRGB(25, 30, 35),
			InputStroke = Color3.fromRGB(45, 50, 60),
			PlaceholderColor = Color3.fromRGB(150, 150, 160),
			ConsoleBackground = Color3.fromRGB(15, 18, 22),
			ConsoleText = Color3.fromRGB(220, 225, 230),
		},
	},
	CurrentTheme = nil,
	ActiveModals = {},
	ModalCount = 0,
}

-- Set default theme
RayfieldModalLibrary.CurrentTheme = RayfieldModalLibrary.Theme.Default

-- Utility Functions
local function Create(instance, properties)
	local obj = Instance.new(instance)
	for prop, value in pairs(properties) do
		obj[prop] = value
	end
	return obj
end

local function Tween(obj, props, duration, style, direction)
	local tweenInfo = TweenInfo.new(duration or 0.3, style or Enum.EasingStyle.Quint, direction or Enum.EasingDirection.Out)
	local tween = TweenService:Create(obj, tweenInfo, props)
	tween:Play()
	return tween
end

local function GetScreenGui()
	-- Find or create the main ScreenGui
	local screenGui
	
	if gethui then
		screenGui = gethui():FindFirstChild("RayfieldModalUI")
		if not screenGui then
			screenGui = Create("ScreenGui", {
				Name = "RayfieldModalUI",
				IgnoreGuiInset = true,
				ResetOnSpawn = false,
				ZIndexBehavior = Enum.ZIndexBehavior.Sibling,
				DisplayOrder = 1000
			})
			screenGui.Parent = gethui()
		end
	elseif syn and syn.protect_gui then
		screenGui = CoreGui:FindFirstChild("RayfieldModalUI")
		if not screenGui then
			screenGui = Create("ScreenGui", {
				Name = "RayfieldModalUI",
				IgnoreGuiInset = true,
				ResetOnSpawn = false,
				ZIndexBehavior = Enum.ZIndexBehavior.Sibling,
				DisplayOrder = 1000
			})
			syn.protect_gui(screenGui)
			screenGui.Parent = CoreGui
		end
	else
		screenGui = CoreGui:FindFirstChild("RayfieldModalUI")
		if not screenGui then
			screenGui = Create("ScreenGui", {
				Name = "RayfieldModalUI",
				IgnoreGuiInset = true,
				ResetOnSpawn = false,
				ZIndexBehavior = Enum.ZIndexBehavior.Sibling,
				DisplayOrder = 1000
			})
			screenGui.Parent = CoreGui
		end
	end
	
	return screenGui
end

-- Create overlay dimming background
local function CreateOverlay(parent)
	local overlay = Create("Frame", {
		Name = "Overlay",
		Size = UDim2.new(1, 0, 1, 0),
		Position = UDim2.new(0, 0, 0, 0),
		BackgroundColor3 = Color3.new(0, 0, 0),
		BackgroundTransparency = 1,
		BorderSizePixel = 0,
		ZIndex = 1,
		Parent = parent
	})
	
	Tween(overlay, {BackgroundTransparency = 0.5}, 0.3)
	
	return overlay
end

-- Create base modal frame
local function CreateModalBase(parent, title, width, height)
	local theme = RayfieldModalLibrary.CurrentTheme
	
	local modal = Create("Frame", {
		Name = "Modal_" .. tostring(RayfieldModalLibrary.ModalCount),
		Size = UDim2.new(0, width or 400, 0, height or 200),
		Position = UDim2.new(0.5, 0, 0.5, 0),
		AnchorPoint = Vector2.new(0.5, 0.5),
		BackgroundColor3 = theme.Background,
		BorderColor3 = theme.ElementStroke,
		BorderSizePixel = 0,
		ZIndex = 2,
		Parent = parent
	})
	
	-- Add corner radius
	Create("UICorner", {
		CornerRadius = UDim.new(0, 8),
		Parent = modal
	})
	
	-- Add stroke
	Create("UIStroke", {
		Color = theme.ElementStroke,
		Thickness = 1,
		Parent = modal
	})
	
	-- Add shadow
	local shadow = Create("ImageLabel", {
		Name = "Shadow",
		Size = UDim2.new(1, 30, 1, 30),
		Position = UDim2.new(0, -15, 0, -15),
		BackgroundTransparency = 1,
		Image = "rbxassetid://6014261993",
		ImageColor3 = theme.Shadow,
		ImageTransparency = 0.5,
		ScaleType = Enum.ScaleType.Slice,
		SliceCenter = Rect.new(49, 49, 450, 450),
		ZIndex = 1,
		Parent = modal
	})
	
	-- Top bar
	local topbar = Create("Frame", {
		Name = "Topbar",
		Size = UDim2.new(1, 0, 0, 45),
		Position = UDim2.new(0, 0, 0, 0),
		BackgroundColor3 = theme.Topbar,
		BorderSizePixel = 0,
		ZIndex = 3,
		Parent = modal
	})
	
	-- Top bar corner fix
	local topbarCorner = Create("Frame", {
		Name = "CornerFix",
		Size = UDim2.new(1, 0, 0, 15),
		Position = UDim2.new(0, 0, 1, -5),
		BackgroundColor3 = theme.Topbar,
		BorderSizePixel = 0,
		ZIndex = 2,
		Parent = topbar
	})
	
	Create("UICorner", {
		CornerRadius = UDim.new(0, 8),
		Parent = topbar
	})
	
	-- Title
	local titleLabel = Create("TextLabel", {
		Name = "Title",
		Size = UDim2.new(1, -50, 1, 0),
		Position = UDim2.new(0, 15, 0, 0),
		BackgroundTransparency = 1,
		Text = title or "Modal",
		TextColor3 = theme.TextColor,
		TextSize = 16,
		Font = Enum.Font.GothamSemibold,
		TextXAlignment = Enum.TextXAlignment.Left,
		ZIndex = 4,
		Parent = topbar
	})
	
	-- Close button
	local closeBtn = Create("TextButton", {
		Name = "Close",
		Size = UDim2.new(0, 30, 0, 30),
		Position = UDim2.new(1, -38, 0.5, 0),
		AnchorPoint = Vector2.new(0, 0.5),
		BackgroundTransparency = 1,
		Text = "",
		ZIndex = 4,
		Parent = topbar
	})
	
	local closeIcon = Create("ImageLabel", {
		Name = "Icon",
		Size = UDim2.new(0, 16, 0, 16),
		Position = UDim2.new(0.5, 0, 0.5, 0),
		AnchorPoint = Vector2.new(0.5, 0.5),
		BackgroundTransparency = 1,
		Image = "rbxassetid://3926305904",
		ImageRectSize = Vector2.new(48, 48),
		ImageRectOffset = Vector2.new(288, 288),
		ImageColor3 = theme.TextColor,
		ImageTransparency = 0.3,
		ZIndex = 5,
		Parent = closeBtn
	})
	
	-- Initial animation
	modal.Size = UDim2.new(0, width or 400, 0, 0)
	modal.BackgroundTransparency = 1
	topbar.BackgroundTransparency = 1
	topbarCorner.BackgroundTransparency = 1
	titleLabel.TextTransparency = 1
	shadow.ImageTransparency = 1
	closeBtn.Visible = false
	
	task.wait()
	
	Tween(modal, {BackgroundTransparency = 0}, 0.2)
	Tween(topbar, {BackgroundTransparency = 0}, 0.2)
	Tween(topbarCorner, {BackgroundTransparency = 0}, 0.2)
	Tween(titleLabel, {TextTransparency = 0}, 0.2)
	Tween(shadow, {ImageTransparency = 0.5}, 0.3)
	Tween(modal, {Size = UDim2.new(0, width or 400, 0, height or 200)}, 0.3, Enum.EasingStyle.Back)
	
	task.wait(0.15)
	closeBtn.Visible = true
	
	return modal, topbar, titleLabel, closeBtn
end

-- Set Theme
function RayfieldModalLibrary:SetTheme(themeName)
	if self.Theme[themeName] then
		self.CurrentTheme = self.Theme[themeName]
	end
end

-- Modal Notification (center screen)
function RayfieldModalLibrary:Notify(data)
	local screenGui = GetScreenGui()
	local theme = self.CurrentTheme
	self.ModalCount = self.ModalCount + 1
	
	local width = 380
	local height = 140
	
	local overlay = CreateOverlay(screenGui)
	local modal, topbar, titleLabel, closeBtn = CreateModalBase(screenGui, data.Title or "Notification", width, height)
	
	-- Content container
	local contentFrame = Create("Frame", {
		Name = "Content",
		Size = UDim2.new(1, -30, 1, -60),
		Position = UDim2.new(0, 15, 0, 50),
		BackgroundTransparency = 1,
		ZIndex = 3,
		Parent = modal
	})
	
	-- Icon (optional)
	local iconSize = 0
	if data.Image then
		local icon = Create("ImageLabel", {
			Name = "Icon",
			Size = UDim2.new(0, 40, 0, 40),
			Position = UDim2.new(0, 0, 0, 10),
			BackgroundTransparency = 1,
			Image = typeof(data.Image) == "number" and "rbxassetid://" .. data.Image or data.Image,
			ImageColor3 = theme.Accent,
			ZIndex = 4,
			Parent = contentFrame
		})
		iconSize = 50
	end
	
	-- Description text
	local descLabel = Create("TextLabel", {
		Name = "Description",
		Size = UDim2.new(1, -iconSize - 10, 1, -20),
		Position = UDim2.new(0, iconSize, 0, 10),
		BackgroundTransparency = 1,
		Text = data.Content or "",
		TextColor3 = theme.TextColor,
		TextSize = 14,
		Font = Enum.Font.Gotham,
		TextXAlignment = Enum.TextXAlignment.Left,
		TextYAlignment = Enum.TextYAlignment.Top,
		TextWrapped = true,
		ZIndex = 4,
		Parent = contentFrame
	})
	descLabel.TextTransparency = 1
	
	Tween(descLabel, {TextTransparency = 0}, 0.2)
	
	-- Close function
	local function closeModal()
		Tween(modal, {Size = UDim2.new(0, width, 0, 0)}, 0.2, Enum.EasingStyle.Back)
		Tween(overlay, {BackgroundTransparency = 1}, 0.2)
		Tween(modal, {BackgroundTransparency = 1}, 0.2)
		Tween(topbar, {BackgroundTransparency = 1}, 0.2)
		Tween(descLabel, {TextTransparency = 1}, 0.15)
		Tween(titleLabel, {TextTransparency = 1}, 0.15)
		
		task.wait(0.25)
		modal:Destroy()
		overlay:Destroy()
	end
	
	closeBtn.MouseButton1Click:Connect(closeModal)
	overlay.InputBegan:Connect(function(input)
		if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
			closeModal()
		end
	end)
	
	-- Auto close after duration
	task.spawn(function()
		local duration = data.Duration or 4
		task.wait(duration)
		if modal and modal.Parent then
			closeModal()
		end
	end)
	
	return modal
end

-- Console/Code Display
function RayfieldModalLibrary:Console(data)
	local screenGui = GetScreenGui()
	local theme = self.CurrentTheme
	self.ModalCount = self.ModalCount + 1
	
	local width = data.Width or 550
	local height = data.Height or 400
	
	local overlay = CreateOverlay(screenGui)
	local modal, topbar, titleLabel, closeBtn = CreateModalBase(screenGui, data.Title or "Console", width, height)
	
	-- Console container
	local consoleFrame = Create("Frame", {
		Name = "ConsoleFrame",
		Size = UDim2.new(1, -20, 1, -60),
		Position = UDim2.new(0, 10, 0, 50),
		BackgroundColor3 = theme.ConsoleBackground,
		BorderSizePixel = 0,
		ZIndex = 3,
		Parent = modal
	})
	
	Create("UICorner", {
		CornerRadius = UDim.new(0, 6),
		Parent = consoleFrame
	})
	
	Create("UIStroke", {
		Color = theme.ElementStroke,
		Thickness = 1,
		Parent = consoleFrame
	})
	
	-- Code/Text display with scrolling
	local scrollingFrame = Create("ScrollingFrame", {
		Name = "ScrollingFrame",
		Size = UDim2.new(1, -10, 1, -10),
		Position = UDim2.new(0, 5, 0, 5),
		BackgroundTransparency = 1,
		ScrollBarThickness = 6,
		ScrollBarImageColor3 = theme.Accent,
		BorderSizePixel = 0,
		CanvasSize = UDim2.new(0, 0, 0, 0),
		ZIndex = 4,
		Parent = consoleFrame
	})
	
	-- Code text
	local codeText = Create("TextLabel", {
		Name = "Code",
		Size = UDim2.new(1, -10, 1, 0),
		Position = UDim2.new(0, 5, 0, 5),
		BackgroundTransparency = 1,
		Text = data.Content or "",
		TextColor3 = theme.ConsoleText,
		TextSize = 13,
		Font = Enum.Font.Code,
		TextXAlignment = Enum.TextXAlignment.Left,
		TextYAlignment = Enum.TextYAlignment.Top,
		TextWrapped = true,
		ZIndex = 5,
		Parent = scrollingFrame
	})
	codeText.TextTransparency = 1
	
	-- Calculate text height for scrolling
	local textBounds = game:GetService("TextService"):GetTextSize(
		data.Content or "",
		13,
		Enum.Font.Code,
		Vector2.new(scrollingFrame.AbsoluteSize.X, math.huge)
	)
	scrollingFrame.CanvasSize = UDim2.new(0, 0, 0, textBounds.Y + 20)
	
	-- Language badge (optional)
	if data.Language then
		local langBadge = Create("Frame", {
			Name = "LangBadge",
			Size = UDim2.new(0, 60, 0, 22),
			Position = UDim2.new(1, -70, 0, 8),
			BackgroundColor3 = theme.Accent,
			BorderSizePixel = 0,
			ZIndex = 6,
			Parent = modal
		})
		
		Create("UICorner", {
			CornerRadius = UDim.new(0, 4),
			Parent = langBadge
		})
		
		Create("TextLabel", {
			Name = "Lang",
			Size = UDim2.new(1, 0, 1, 0),
			BackgroundTransparency = 1,
			Text = string.upper(data.Language),
			TextColor3 = Color3.new(1, 1, 1),
			TextSize = 10,
			Font = Enum.Font.GothamBold,
			ZIndex = 7,
			Parent = langBadge
		})
	end
	
	-- Copy button
	local copyBtn = Create("TextButton", {
		Name = "Copy",
		Size = UDim2.new(0, 80, 0, 28),
		Position = UDim2.new(0, 10, 1, -38),
		BackgroundColor3 = theme.ElementBackground,
		BorderSizePixel = 0,
		Text = "Copy",
		TextColor3 = theme.TextColor,
		TextSize = 12,
		Font = Enum.Font.GothamSemibold,
		ZIndex = 5,
		Parent = modal
	})
	
	Create("UICorner", {
		CornerRadius = UDim.new(0, 4),
		Parent = copyBtn
	})
	
	Create("UIStroke", {
		Color = theme.ElementStroke,
		Thickness = 1,
		Parent = copyBtn
	})
	
	copyBtn.MouseButton1Click:Connect(function()
		if setclipboard then
			setclipboard(data.Content or "")
			copyBtn.Text = "Copied!"
			copyBtn.BackgroundColor3 = theme.Success
			task.wait(1)
			copyBtn.Text = "Copy"
			copyBtn.BackgroundColor3 = theme.ElementBackground
		end
	end)
	
	-- Close button
	local closeBtn = Create("TextButton", {
		Name = "CloseBtn",
		Size = UDim2.new(0, 80, 0, 28),
		Position = UDim2.new(1, -90, 1, -38),
		BackgroundColor3 = theme.Accent,
		BorderSizePixel = 0,
		Text = "Close",
		TextColor3 = Color3.new(1, 1, 1),
		TextSize = 12,
		Font = Enum.Font.GothamSemibold,
		ZIndex = 5,
		Parent = modal
	})
	
	Create("UICorner", {
		CornerRadius = UDim.new(0, 4),
		Parent = closeBtn
	})
	
	Tween(codeText, {TextTransparency = 0}, 0.2)
	
	-- Close function
	local function closeModal()
		Tween(modal, {Size = UDim2.new(0, width, 0, 0)}, 0.2, Enum.EasingStyle.Back)
		Tween(overlay, {BackgroundTransparency = 1}, 0.2)
		Tween(modal, {BackgroundTransparency = 1}, 0.2)
		Tween(topbar, {BackgroundTransparency = 1}, 0.2)
		Tween(codeText, {TextTransparency = 1}, 0.15)
		Tween(titleLabel, {TextTransparency = 1}, 0.15)
		
		task.wait(0.25)
		modal:Destroy()
		overlay:Destroy()
	end
	
	closeBtn.MouseButton1Click:Connect(closeModal)
	closeBtn.MouseButton1Click:Connect(closeModal)
	overlay.InputBegan:Connect(function(input)
		if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
			closeModal()
		end
	end)
	
	return modal
end

-- Yes/No Confirmation Dialog
function RayfieldModalLibrary:Confirm(data)
	local screenGui = GetScreenGui()
	local theme = self.CurrentTheme
	self.ModalCount = self.ModalCount + 1
	
	local width = 380
	local height = 160
	
	local overlay = CreateOverlay(screenGui)
	local modal, topbar, titleLabel, closeBtn = CreateModalBase(screenGui, data.Title or "Confirm", width, height)
	
	-- Content
	local contentFrame = Create("Frame", {
		Name = "Content",
		Size = UDim2.new(1, -30, 1, -110),
		Position = UDim2.new(0, 15, 0, 50),
		BackgroundTransparency = 1,
		ZIndex = 3,
		Parent = modal
	})
	
	-- Description
	local descLabel = Create("TextLabel", {
		Name = "Description",
		Size = UDim2.new(1, 0, 1, 0),
		Position = UDim2.new(0, 0, 0, 0),
		BackgroundTransparency = 1,
		Text = data.Content or "Are you sure?",
		TextColor3 = theme.TextColor,
		TextSize = 14,
		Font = Enum.Font.Gotham,
		TextXAlignment = Enum.TextXAlignment.Left,
		TextYAlignment = Enum.TextYAlignment.Top,
		TextWrapped = true,
		ZIndex = 4,
		Parent = contentFrame
	})
	descLabel.TextTransparency = 1
	Tween(descLabel, {TextTransparency = 0}, 0.2)
	
	-- Buttons container
	local btnContainer = Create("Frame", {
		Name = "Buttons",
		Size = UDim2.new(1, -30, 0, 36),
		Position = UDim2.new(0, 15, 1, -50),
		BackgroundTransparency = 1,
		ZIndex = 3,
		Parent = modal
	})
	
	-- No button
	local noBtn = Create("TextButton", {
		Name = "No",
		Size = UDim2.new(0.5, -5, 1, 0),
		Position = UDim2.new(0, 0, 0, 0),
		BackgroundColor3 = theme.SecondaryBackground,
		BorderSizePixel = 0,
		Text = data.NoText or "No",
		TextColor3 = theme.TextColor,
		TextSize = 13,
		Font = Enum.Font.GothamSemibold,
		ZIndex = 4,
		Parent = btnContainer
	})
	
	Create("UICorner", {
		CornerRadius = UDim.new(0, 6),
		Parent = noBtn
	})
	
	Create("UIStroke", {
		Color = theme.ElementStroke,
		Thickness = 1,
		Parent = noBtn
	})
	
	-- Yes button
	local yesBtn = Create("TextButton", {
		Name = "Yes",
		Size = UDim2.new(0.5, -5, 1, 0),
		Position = UDim2.new(0.5, 5, 0, 0),
		BackgroundColor3 = theme.Accent,
		BorderSizePixel = 0,
		Text = data.YesText or "Yes",
		TextColor3 = Color3.new(1, 1, 1),
		TextSize = 13,
		Font = Enum.Font.GothamSemibold,
		ZIndex = 4,
		Parent = btnContainer
	})
	
	Create("UICorner", {
		CornerRadius = UDim.new(0, 6),
		Parent = yesBtn
	})
	
	-- Button hover effects
	noBtn.MouseEnter:Connect(function()
		Tween(noBtn, {BackgroundColor3 = theme.ElementBackground}, 0.15)
	end)
	noBtn.MouseLeave:Connect(function()
		Tween(noBtn, {BackgroundColor3 = theme.SecondaryBackground}, 0.15)
	end)
	
	yesBtn.MouseEnter:Connect(function()
		Tween(yesBtn, {BackgroundColor3 = theme.AccentHover}, 0.15)
	end)
	yesBtn.MouseLeave:Connect(function()
		Tween(yesBtn, {BackgroundColor3 = theme.Accent}, 0.15)
	end)
	
	-- Close function
	local function closeModal()
		Tween(modal, {Size = UDim2.new(0, width, 0, 0)}, 0.2, Enum.EasingStyle.Back)
		Tween(overlay, {BackgroundTransparency = 1}, 0.2)
		Tween(modal, {BackgroundTransparency = 1}, 0.2)
		Tween(topbar, {BackgroundTransparency = 1}, 0.2)
		Tween(descLabel, {TextTransparency = 1}, 0.15)
		Tween(titleLabel, {TextTransparency = 1}, 0.15)
		
		task.wait(0.25)
		modal:Destroy()
		overlay:Destroy()
	end
	
	-- Button callbacks
	noBtn.MouseButton1Click:Connect(function()
		closeModal()
		if data.Callback then
			data.Callback(false)
		end
	end)
	
	yesBtn.MouseButton1Click:Connect(function()
		closeModal()
		if data.Callback then
			data.Callback(true)
		end
	end)
	
	closeBtn.MouseButton1Click:Connect(function()
		closeModal()
		if data.Callback then
			data.Callback(false)
		end
	end)
	
	return modal
end

-- Input Prompt
function RayfieldModalLibrary:Prompt(data)
	local screenGui = GetScreenGui()
	local theme = self.CurrentTheme
	self.ModalCount = self.ModalCount + 1
	
	local width = 380
	local height = 175
	
	local overlay = CreateOverlay(screenGui)
	local modal, topbar, titleLabel, closeBtn = CreateModalBase(screenGui, data.Title or "Input", width, height)
	
	-- Content
	local contentFrame = Create("Frame", {
		Name = "Content",
		Size = UDim2.new(1, -30, 1, -110),
		Position = UDim2.new(0, 15, 0, 50),
		BackgroundTransparency = 1,
		ZIndex = 3,
		Parent = modal
	})
	
	-- Description (optional)
	local yOffset = 0
	if data.Content then
		local descLabel = Create("TextLabel", {
			Name = "Description",
			Size = UDim2.new(1, 0, 0, 20),
			Position = UDim2.new(0, 0, 0, 0),
			BackgroundTransparency = 1,
			Text = data.Content,
			TextColor3 = theme.TextColor,
			TextSize = 13,
			Font = Enum.Font.Gotham,
			TextXAlignment = Enum.TextXAlignment.Left,
			TextWrapped = true,
			ZIndex = 4,
			Parent = contentFrame
		})
		descLabel.TextTransparency = 1
		Tween(descLabel, {TextTransparency = 0}, 0.2)
		yOffset = 28
	end
	
	-- Input box
	local inputBox = Create("TextBox", {
		Name = "Input",
		Size = UDim2.new(1, 0, 0, 38),
		Position = UDim2.new(0, 0, 0, yOffset),
		BackgroundColor3 = theme.InputBackground,
		BorderSizePixel = 0,
		Text = data.Default or "",
		PlaceholderText = data.Placeholder or "Enter text...",
		PlaceholderColor3 = theme.PlaceholderColor,
		TextColor3 = theme.TextColor,
		TextSize = 14,
		Font = Enum.Font.Gotham,
		TextXAlignment = Enum.TextXAlignment.Left,
		ZIndex = 4,
		Parent = contentFrame
	})
	
	Create("UICorner", {
		CornerRadius = UDim.new(0, 6),
		Parent = inputBox
	})
	
	Create("UIStroke", {
		Color = theme.InputStroke,
		Thickness = 1,
		Parent = inputBox
	})
	
	Create("UIPadding", {
		PaddingLeft = UDim.new(0, 12),
		PaddingRight = UDim.new(0, 12),
		Parent = inputBox
	})
	
	-- Buttons container
	local btnContainer = Create("Frame", {
		Name = "Buttons",
		Size = UDim2.new(1, -30, 0, 36),
		Position = UDim2.new(0, 15, 1, -50),
		BackgroundTransparency = 1,
		ZIndex = 3,
		Parent = modal
	})
	
	-- Cancel button
	local cancelBtn = Create("TextButton", {
		Name = "Cancel",
		Size = UDim2.new(0.5, -5, 1, 0),
		Position = UDim2.new(0, 0, 0, 0),
		BackgroundColor3 = theme.SecondaryBackground,
		BorderSizePixel = 0,
		Text = "Cancel",
		TextColor3 = theme.TextColor,
		TextSize = 13,
		Font = Enum.Font.GothamSemibold,
		ZIndex = 4,
		Parent = btnContainer
	})
	
	Create("UICorner", {
		CornerRadius = UDim.new(0, 6),
		Parent = cancelBtn
	})
	
	Create("UIStroke", {
		Color = theme.ElementStroke,
		Thickness = 1,
		Parent = cancelBtn
	})
	
	-- Confirm button
	local confirmBtn = Create("TextButton", {
		Name = "Confirm",
		Size = UDim2.new(0.5, -5, 1, 0),
		Position = UDim2.new(0.5, 5, 0, 0),
		BackgroundColor3 = theme.Accent,
		BorderSizePixel = 0,
		Text = "Confirm",
		TextColor3 = Color3.new(1, 1, 1),
		TextSize = 13,
		Font = Enum.Font.GothamSemibold,
		ZIndex = 4,
		Parent = btnContainer
	})
	
	Create("UICorner", {
		CornerRadius = UDim.new(0, 6),
		Parent = confirmBtn
	})
	
	-- Button hover effects
	cancelBtn.MouseEnter:Connect(function()
		Tween(cancelBtn, {BackgroundColor3 = theme.ElementBackground}, 0.15)
	end)
	cancelBtn.MouseLeave:Connect(function()
		Tween(cancelBtn, {BackgroundColor3 = theme.SecondaryBackground}, 0.15)
	end)
	
	confirmBtn.MouseEnter:Connect(function()
		Tween(confirmBtn, {BackgroundColor3 = theme.AccentHover}, 0.15)
	end)
	confirmBtn.MouseLeave:Connect(function()
		Tween(confirmBtn, {BackgroundColor3 = theme.Accent}, 0.15)
	end)
	
	-- Close function
	local function closeModal()
		Tween(modal, {Size = UDim2.new(0, width, 0, 0)}, 0.2, Enum.EasingStyle.Back)
		Tween(overlay, {BackgroundTransparency = 1}, 0.2)
		Tween(modal, {BackgroundTransparency = 1}, 0.2)
		Tween(topbar, {BackgroundTransparency = 1}, 0.2)
		Tween(titleLabel, {TextTransparency = 1}, 0.15)
		
		task.wait(0.25)
		modal:Destroy()
		overlay:Destroy()
	end
	
	-- Button callbacks
	cancelBtn.MouseButton1Click:Connect(function()
		closeModal()
		if data.Callback then
			data.Callback(nil)
		end
	end)
	
	confirmBtn.MouseButton1Click:Connect(function()
		closeModal()
		if data.Callback then
			data.Callback(inputBox.Text)
		end
	end)
	
	closeBtn.MouseButton1Click:Connect(function()
		closeModal()
		if data.Callback then
			data.Callback(nil)
		end
	end)
	
	-- Enter key to confirm
	inputBox.FocusLost:Connect(function(enterPressed)
		if enterPressed then
			closeModal()
			if data.Callback then
				data.Callback(inputBox.Text)
			end
		end
	end)
	
	-- Auto focus input
	task.wait(0.2)
	inputBox:CaptureFocus()
	
	return modal
end

-- Alert Dialog (simple OK dialog)
function RayfieldModalLibrary:Alert(data)
	local screenGui = GetScreenGui()
	local theme = self.CurrentTheme
	self.ModalCount = self.ModalCount + 1
	
	local width = 380
	local height = 160
	
	local overlay = CreateOverlay(screenGui)
	local modal, topbar, titleLabel, closeBtn = CreateModalBase(screenGui, data.Title or "Alert", width, height)
	
	-- Content
	local contentFrame = Create("Frame", {
		Name = "Content",
		Size = UDim2.new(1, -30, 1, -110),
		Position = UDim2.new(0, 15, 0, 50),
		BackgroundTransparency = 1,
		ZIndex = 3,
		Parent = modal
	})
	
	-- Description
	local descLabel = Create("TextLabel", {
		Name = "Description",
		Size = UDim2.new(1, 0, 1, 0),
		Position = UDim2.new(0, 0, 0, 0),
		BackgroundTransparency = 1,
		Text = data.Content or "",
		TextColor3 = theme.TextColor,
		TextSize = 14,
		Font = Enum.Font.Gotham,
		TextXAlignment = Enum.TextXAlignment.Left,
		TextYAlignment = Enum.TextYAlignment.Top,
		TextWrapped = true,
		ZIndex = 4,
		Parent = contentFrame
	})
	descLabel.TextTransparency = 1
	Tween(descLabel, {TextTransparency = 0}, 0.2)
	
	-- OK button
	local okBtn = Create("TextButton", {
		Name = "OK",
		Size = UDim2.new(0, 120, 0, 36),
		Position = UDim2.new(0.5, -60, 1, -50),
		BackgroundColor3 = theme.Accent,
		BorderSizePixel = 0,
		Text = data.ButtonText or "OK",
		TextColor3 = Color3.new(1, 1, 1),
		TextSize = 13,
		Font = Enum.Font.GothamSemibold,
		ZIndex = 4,
		Parent = modal
	})
	
	Create("UICorner", {
		CornerRadius = UDim.new(0, 6),
		Parent = okBtn
	})
	
	okBtn.MouseEnter:Connect(function()
		Tween(okBtn, {BackgroundColor3 = theme.AccentHover}, 0.15)
	end)
	okBtn.MouseLeave:Connect(function()
		Tween(okBtn, {BackgroundColor3 = theme.Accent}, 0.15)
	end)
	
	-- Close function
	local function closeModal()
		Tween(modal, {Size = UDim2.new(0, width, 0, 0)}, 0.2, Enum.EasingStyle.Back)
		Tween(overlay, {BackgroundTransparency = 1}, 0.2)
		Tween(modal, {BackgroundTransparency = 1}, 0.2)
		Tween(topbar, {BackgroundTransparency = 1}, 0.2)
		Tween(descLabel, {TextTransparency = 1}, 0.15)
		Tween(titleLabel, {TextTransparency = 1}, 0.15)
		
		task.wait(0.25)
		modal:Destroy()
		overlay:Destroy()
		
		if data.Callback then
			data.Callback()
		end
	end
	
	okBtn.MouseButton1Click:Connect(closeModal)
	closeBtn.MouseButton1Click:Connect(closeModal)
	
	return modal
end

-- Loading Dialog
function RayfieldModalLibrary:Loading(data)
	local screenGui = GetScreenGui()
	local theme = self.CurrentTheme
	self.ModalCount = self.ModalCount + 1
	
	local width = 300
	local height = 130
	
	local overlay = CreateOverlay(screenGui)
	local modal, topbar, titleLabel, closeBtn = CreateModalBase(screenGui, data.Title or "Loading", width, height)
	closeBtn.Visible = false
	
	-- Content
	local contentFrame = Create("Frame", {
		Name = "Content",
		Size = UDim2.new(1, -30, 1, -60),
		Position = UDim2.new(0, 15, 0, 50),
		BackgroundTransparency = 1,
		ZIndex = 3,
		Parent = modal
	})
	
	-- Loading spinner
	local spinner = Create("ImageLabel", {
		Name = "Spinner",
		Size = UDim2.new(0, 32, 0, 32),
		Position = UDim2.new(0.5, 0, 0, 10),
		AnchorPoint = Vector2.new(0.5, 0),
		BackgroundTransparency = 1,
		Image = "rbxassetid://6014261993",
		ImageColor3 = theme.Accent,
		ZIndex = 4,
		Parent = contentFrame
	})
	
	-- Status text
	local statusLabel = Create("TextLabel", {
		Name = "Status",
		Size = UDim2.new(1, 0, 0, 30),
		Position = UDim2.new(0, 0, 0, 50),
		BackgroundTransparency = 1,
		Text = data.Content or "Please wait...",
		TextColor3 = theme.TextColor,
		TextSize = 14,
		Font = Enum.Font.Gotham,
		ZIndex = 4,
		Parent = contentFrame
	})
	statusLabel.TextTransparency = 1
	Tween(statusLabel, {TextTransparency = 0}, 0.2)
	
	-- Spinner rotation animation
	local rotation = 0
	local connection
	connection = RunService.Heartbeat:Connect(function()
		rotation = rotation + 5
		spinner.Rotation = rotation
	end)
	
	-- Return control object
	local control = {}
	
	function control:Update(text)
		statusLabel.Text = text
	end
	
	function control:Close()
		connection:Disconnect()
		Tween(modal, {Size = UDim2.new(0, width, 0, 0)}, 0.2, Enum.EasingStyle.Back)
		Tween(overlay, {BackgroundTransparency = 1}, 0.2)
		Tween(modal, {BackgroundTransparency = 1}, 0.2)
		Tween(topbar, {BackgroundTransparency = 1}, 0.2)
		
		task.wait(0.25)
		modal:Destroy()
		overlay:Destroy()
	end
	
	return control
end

return RayfieldModalLibrary
