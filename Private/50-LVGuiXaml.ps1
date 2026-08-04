# The GUI's markup, kept apart from its behaviour so the window logic in
# Public/Show-LogVerdictGui.ps1 stays readable.
#
# Loaded with [Windows.Markup.XamlReader]::Parse, which is stricter than a compiled
# XAML build: no x:Class, no design-time namespaces, and every element the code
# reaches for must carry an x:Name. Tests/LogVerdict.Tests.ps1 asserts that every
# name FindName() is called with actually exists here, because a rename that only
# breaks at runtime would otherwise ship.
#
# Palette is Catppuccin Mocha. WPF's stock ListView, ScrollBar and CheckBox are all
# light-themed and ignore a dark window background, so each one is templated below
# rather than merely recoloured - a half-themed control is worse than none.
#
# The default size is in device-independent units, so it is multiplied by the display
# scale before it reaches the screen: at the 125% that Windows picks for most 1080p
# laptops, 760 becomes 950 real pixels against a work area of roughly 1032. Anything
# above about 800 here pushes the status bar behind the taskbar on a 1080p machine.

function Get-LVGuiXaml {
    [CmdletBinding()]
    param()

    $xaml = @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="LogVerdict"
    Height="800" Width="1440" MinHeight="650" MinWidth="1120"
    WindowStartupLocation="CenterScreen"
    Background="{DynamicResource Base}"
    TextOptions.TextFormattingMode="Ideal"
    UseLayoutRounding="True"
    FontFamily="Segoe UI Variable Text, Segoe UI"
    FontSize="13">

  <Window.Resources>

    <SolidColorBrush x:Key="Base"     Color="#08111f"/>
    <SolidColorBrush x:Key="Mantle"   Color="#06101e"/>
    <SolidColorBrush x:Key="Crust"    Color="#040a13"/>
    <SolidColorBrush x:Key="Surface0" Color="#102239"/>
    <SolidColorBrush x:Key="Surface1" Color="#1a3554"/>
    <SolidColorBrush x:Key="Surface2" Color="#2a4a6b"/>
    <SolidColorBrush x:Key="Overlay0" Color="#54708c"/>
    <SolidColorBrush x:Key="Overlay1" Color="#6e89a4"/>
    <SolidColorBrush x:Key="Text"     Color="#f5f7fb"/>
    <SolidColorBrush x:Key="Subtext1" Color="#d1d9e6"/>
    <SolidColorBrush x:Key="Subtext0" Color="#a9b8cb"/>
    <SolidColorBrush x:Key="Blue"     Color="#60a5fa"/>
    <SolidColorBrush x:Key="Lavender" Color="#82b4ff"/>
    <SolidColorBrush x:Key="Mauve"    Color="#a78bfa"/>
    <SolidColorBrush x:Key="Red"      Color="#ff6b6b"/>
    <SolidColorBrush x:Key="Peach"    Color="#ffaa64"/>
    <SolidColorBrush x:Key="Yellow"   Color="#ffd166"/>
    <SolidColorBrush x:Key="Green"    Color="#5dd39e"/>
    <SolidColorBrush x:Key="Sky"      Color="#56d4e8"/>
    <SolidColorBrush x:Key="AccentInk"      Color="#06101e"/>
    <SolidColorBrush x:Key="AccentPressed"  Color="#74a8fc"/>
    <SolidColorBrush x:Key="RowDivider"     Color="#0f2138"/>
    <SolidColorBrush x:Key="RowHover"       Color="#0d2038"/>
    <SolidColorBrush x:Key="NavBorder"      Color="#275486"/>
    <SolidColorBrush x:Key="SoftPanel"      Color="#0b182a"/>
    <SolidColorBrush x:Key="BluePanel"      Color="#102b4d"/>
    <SolidColorBrush x:Key="NavIconActive"  Color="#16355a"/>
    <SolidColorBrush x:Key="SuccessPanel"   Color="#0b2b2b"/>
    <SolidColorBrush x:Key="ElevationPanel" Color="#13243a"/>
    <SolidColorBrush x:Key="StatusIcon"     Color="#14335a"/>
    <SolidColorBrush x:Key="WarningBorder"  Color="#6d4b2d"/>
    <SolidColorBrush x:Key="WarningCard"    Color="#141a26"/>
    <SolidColorBrush x:Key="WarningIcon"    Color="#3a271d"/>
    <SolidColorBrush x:Key="InfoPanel"      Color="#0a2a35"/>
    <SolidColorBrush x:Key="CoveragePanel"  Color="#121c29"/>
    <SolidColorBrush x:Key="SuccessLine"    Color="#286f60"/>
    <SolidColorBrush x:Key="SuccessIcon"    Color="#153b38"/>
    <SolidColorBrush x:Key="LogBackground"  Color="#071321"/>

    <!-- Muted TEXT. Overlay0 and Overlay1 are dim enough to fail WCAG AA for body text
         (measured 3.36:1 and 4.44:1 on base), so they are now used only for borders and
         dividers, where the 3:1 non-text threshold applies. This tone measures 5.81:1 on
         base, 6.22:1 on mantle and 6.64:1 on crust - it clears AA on every surface the
         window actually paints text on. Same value the HTML report uses, so the two
         outputs stay visually consistent. -->
    <SolidColorBrush x:Key="TextMuted" Color="#8fa4bc"/>

    <!-- A custom ControlTemplate keeps the framework's dotted focus adorner, which is
         effectively invisible on a dark surface. WCAG 2.4.7 wants focus visible and
         1.4.11 wants it at 3:1, so keyboard focus draws an accent ring instead.
         Unrelated to the no-keyboard-shortcuts policy: this is focus visibility, not
         an accelerator. -->
    <Style x:Key="LVFocusVisual">
      <Setter Property="Control.Template">
        <Setter.Value>
          <ControlTemplate>
            <Rectangle Margin="-3" StrokeThickness="2" Stroke="{DynamicResource Blue}"
                       RadiusX="7" RadiusY="7" SnapsToDevicePixels="True"/>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Scrollbars. The stock ones are light grey slabs that survive any amount of
         window recolouring, so they are replaced outright. -->
    <Style x:Key="ScrollThumb" TargetType="Thumb">
      <Setter Property="OverridesDefaultStyle" Value="True"/>
      <Setter Property="IsTabStop" Value="False"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Thumb">
            <Border x:Name="Bar" CornerRadius="4" Margin="3,2,3,2" Background="{DynamicResource Surface1}"/>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bar" Property="Background" Value="{DynamicResource Overlay0}"/>
              </Trigger>
              <Trigger Property="IsDragging" Value="True">
                <Setter TargetName="Bar" Property="Background" Value="{DynamicResource Overlay1}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="ScrollBar">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Width" Value="12"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ScrollBar">
            <Grid Background="Transparent">
              <Track x:Name="PART_Track" IsDirectionReversed="True">
                <Track.DecreaseRepeatButton>
                  <RepeatButton Command="ScrollBar.PageUpCommand" Opacity="0" Focusable="False"/>
                </Track.DecreaseRepeatButton>
                <Track.Thumb>
                  <Thumb Style="{StaticResource ScrollThumb}"/>
                </Track.Thumb>
                <Track.IncreaseRepeatButton>
                  <RepeatButton Command="ScrollBar.PageDownCommand" Opacity="0" Focusable="False"/>
                </Track.IncreaseRepeatButton>
              </Track>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="Orientation" Value="Horizontal">
                <Setter Property="Height" Value="12"/>
                <Setter Property="Width" Value="Auto"/>
                <Setter TargetName="PART_Track" Property="IsDirectionReversed" Value="False"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Buttons -->
    <Style x:Key="BaseButton" TargetType="Button">
      <Setter Property="FocusVisualStyle" Value="{DynamicResource LVFocusVisual}"/>
      <Setter Property="Foreground" Value="{DynamicResource Text}"/>
      <Setter Property="Background" Value="{DynamicResource Surface0}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Surface1}"/>
      <Setter Property="Padding" Value="14,7"/>
      <Setter Property="SnapsToDevicePixels" Value="True"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Chrome"
                    Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="1"
                    CornerRadius="6">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                                Margin="{TemplateBinding Padding}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Chrome" Property="Background" Value="{DynamicResource Surface1}"/>
                <Setter TargetName="Chrome" Property="BorderBrush" Value="{DynamicResource Surface2}"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="Chrome" Property="Background" Value="{DynamicResource Surface2}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="Chrome" Property="Background" Value="{DynamicResource Mantle}"/>
                <Setter TargetName="Chrome" Property="BorderBrush" Value="{DynamicResource Surface0}"/>
                <Setter Property="Foreground" Value="{DynamicResource Overlay0}"/>
                <Setter Property="Cursor" Value="Arrow"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="AccentButton" TargetType="Button" BasedOn="{StaticResource BaseButton}">
      <Setter Property="FocusVisualStyle" Value="{DynamicResource LVFocusVisual}"/>
      <Setter Property="Foreground" Value="{DynamicResource AccentInk}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="14,9"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Chrome" Background="{DynamicResource Blue}" CornerRadius="6">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                                Margin="{TemplateBinding Padding}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Chrome" Property="Background" Value="{DynamicResource Lavender}"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="Chrome" Property="Background" Value="{DynamicResource AccentPressed}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="Chrome" Property="Background" Value="{DynamicResource Surface0}"/>
                <Setter Property="Foreground" Value="{DynamicResource Overlay0}"/>
                <Setter Property="Cursor" Value="Arrow"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Verdict chips double as the filter. Checked = that verdict is visible. -->
    <Style x:Key="ChipToggle" TargetType="ToggleButton">
      <Setter Property="FocusVisualStyle" Value="{DynamicResource LVFocusVisual}"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Margin" Value="0,0,0,6"/>
      <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
      <Setter Property="Foreground" Value="{DynamicResource Subtext0}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ToggleButton">
            <Border x:Name="Chrome" CornerRadius="6" Background="{DynamicResource Mantle}"
                    BorderBrush="{DynamicResource Surface0}" BorderThickness="1" Padding="10,7">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="6"/>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <Border x:Name="Dot" Grid.Column="0" Width="6" Height="6" CornerRadius="3"
                        VerticalAlignment="Center" Background="{TemplateBinding Tag}"/>
                <ContentPresenter Grid.Column="1" Margin="10,0,0,0" VerticalAlignment="Center"/>
              </Grid>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Chrome" Property="Background" Value="{DynamicResource Surface0}"/>
                <Setter TargetName="Chrome" Property="BorderBrush" Value="{DynamicResource Surface2}"/>
                <Setter Property="Foreground" Value="{DynamicResource Text}"/>
              </Trigger>
              <Trigger Property="IsChecked" Value="False">
                <Setter TargetName="Dot" Property="Opacity" Value="0.25"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Chrome" Property="BorderBrush" Value="{DynamicResource Overlay0}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="CheckBox">
      <Setter Property="FocusVisualStyle" Value="{DynamicResource LVFocusVisual}"/>
      <Setter Property="Foreground" Value="{DynamicResource Subtext1}"/>
      <Setter Property="Margin" Value="0,0,0,9"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="CheckBox">
            <StackPanel Orientation="Horizontal" Background="Transparent">
              <Border x:Name="Box" Width="16" Height="16" CornerRadius="4"
                      Background="{DynamicResource Crust}" BorderBrush="{DynamicResource Surface2}"
                      BorderThickness="1" VerticalAlignment="Center">
                <Path x:Name="Tick" Visibility="Collapsed" Stretch="Uniform" Margin="3"
                      Data="M 0,5 L 4,9 L 11,0" Stroke="{DynamicResource AccentInk}" StrokeThickness="2.2"
                      StrokeEndLineCap="Round" StrokeStartLineCap="Round"/>
              </Border>
              <ContentPresenter Margin="9,0,0,0" VerticalAlignment="Center"/>
            </StackPanel>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Box" Property="Background" Value="{DynamicResource Blue}"/>
                <Setter TargetName="Box" Property="BorderBrush" Value="{DynamicResource Blue}"/>
                <Setter TargetName="Tick" Property="Visibility" Value="Visible"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Box" Property="BorderBrush" Value="{DynamicResource Lavender}"/>
                <Setter Property="Foreground" Value="{DynamicResource Text}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Foreground" Value="{DynamicResource Overlay0}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="TextBox">
      <Setter Property="FocusVisualStyle" Value="{DynamicResource LVFocusVisual}"/>
      <Setter Property="Foreground" Value="{DynamicResource Text}"/>
      <Setter Property="CaretBrush" Value="{DynamicResource Blue}"/>
      <Setter Property="SelectionBrush" Value="{DynamicResource Blue}"/>
      <Setter Property="Background" Value="{DynamicResource Crust}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Surface1}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="8,6"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="Chrome" CornerRadius="6"
                    Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"
                            VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsKeyboardFocusWithin" Value="True">
                <Setter TargetName="Chrome" Property="BorderBrush" Value="{DynamicResource Blue}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="FilterCombo" TargetType="ComboBox">
      <Setter Property="FocusVisualStyle" Value="{DynamicResource LVFocusVisual}"/>
      <Setter Property="Foreground" Value="{DynamicResource Text}"/>
      <Setter Property="Background" Value="{DynamicResource Crust}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Surface1}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="7,4"/>
      <Setter Property="MinHeight" Value="30"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
    </Style>

    <Style TargetType="ComboBoxItem">
      <Setter Property="Foreground" Value="{DynamicResource Text}"/>
      <Setter Property="Background" Value="{DynamicResource Crust}"/>
      <Setter Property="Padding" Value="7,5"/>
    </Style>

    <!-- Section heading inside the detail pane -->
    <Style x:Key="SectionLabel" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{DynamicResource TextMuted}"/>
      <Setter Property="FontSize" Value="10.5"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Margin" Value="0,16,0,5"/>
    </Style>

    <Style x:Key="BodyText" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{DynamicResource Subtext1}"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="LineHeight" Value="19"/>
    </Style>

    <Style x:Key="PanelLabel" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{DynamicResource TextMuted}"/>
      <Setter Property="FontSize" Value="10.5"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Margin" Value="0,0,0,9"/>
    </Style>

    <!-- Findings list. Stock ListViewItem paints a blue selection and a white
         background on hover; both are replaced here. -->
    <Style x:Key="FindingRow" TargetType="ListViewItem">
      <!-- Without this a screen reader reads the row's object graph aloud, hex colour
           codes and search haystack included. AutomationName is a plain sentence built
           in ConvertTo-LVGuiRow. -->
      <Setter Property="AutomationProperties.Name" Value="{Binding AutomationName}"/>
      <Setter Property="Foreground" Value="{DynamicResource Subtext1}"/>
      <Setter Property="Padding" Value="0"/>
      <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ListViewItem">
            <Border x:Name="Row" Background="Transparent" BorderThickness="0,0,0,1"
                    BorderBrush="{DynamicResource RowDivider}" Padding="0,7">
              <GridViewRowPresenter VerticalAlignment="Center"
                                    Columns="{TemplateBinding GridView.ColumnCollection}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Row" Property="Background" Value="{DynamicResource RowHover}"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Row" Property="Background" Value="{DynamicResource Surface0}"/>
                <Setter Property="Foreground" Value="{DynamicResource Text}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="GridViewColumnHeader">
      <Setter Property="Foreground" Value="{DynamicResource TextMuted}"/>
      <Setter Property="FontSize" Value="10.5"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="HorizontalContentAlignment" Value="Left"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="GridViewColumnHeader">
            <Border x:Name="Chrome" Background="{DynamicResource Mantle}"
                    BorderBrush="{DynamicResource Surface0}" BorderThickness="0,0,0,1"
                    Padding="10,8">
              <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Chrome" Property="Background" Value="{DynamicResource Surface0}"/>
                <Setter Property="Foreground" Value="{DynamicResource Text}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="GridSplitter">
      <Setter Property="Background" Value="{DynamicResource Mantle}"/>
      <Setter Property="Width" Value="5"/>
    </Style>

    <Style TargetType="ProgressBar">
      <Setter Property="Foreground" Value="{DynamicResource Blue}"/>
      <Setter Property="Background" Value="{DynamicResource Surface0}"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Height" Value="3"/>
    </Style>

    <Style x:Key="NavButton" TargetType="ToggleButton">
      <Setter Property="FocusVisualStyle" Value="{DynamicResource LVFocusVisual}"/>
      <Setter Property="Foreground" Value="{DynamicResource Subtext0}"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderBrush" Value="Transparent"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
      <Setter Property="Padding" Value="10,9"/>
      <Setter Property="Margin" Value="0,0,0,5"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ToggleButton">
            <Border x:Name="NavChrome" Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="7">
              <ContentPresenter Margin="{TemplateBinding Padding}"
                                HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="NavChrome" Property="Background" Value="{DynamicResource RowHover}"/>
                <Setter Property="Foreground" Value="{DynamicResource Text}"/>
              </Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="NavChrome" Property="Background" Value="{DynamicResource BluePanel}"/>
                <Setter TargetName="NavChrome" Property="BorderBrush" Value="{DynamicResource NavBorder}"/>
                <Setter Property="Foreground" Value="{DynamicResource Blue}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="{DynamicResource SoftPanel}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Surface1}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius" Value="10"/>
      <Setter Property="Padding" Value="16"/>
    </Style>

    <Style x:Key="MetricValue" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{DynamicResource Text}"/>
      <Setter Property="FontSize" Value="25"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>

    <Style x:Key="PageTitle" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{DynamicResource Text}"/>
      <Setter Property="FontSize" Value="24"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>

    <Style x:Key="PageSubtitle" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{DynamicResource TextMuted}"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Margin" Value="0,3,0,0"/>
    </Style>

  </Window.Resources>

  <Grid>
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="224"/>
      <ColumnDefinition Width="*"/>
    </Grid.ColumnDefinitions>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- ============ Navigation rail ============ -->
    <Border Grid.Column="0" Grid.RowSpan="3" Background="{DynamicResource Mantle}"
            BorderBrush="{DynamicResource Surface1}" BorderThickness="0,0,1,0" Padding="16,20,16,16">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="2,0,0,28">
          <Border Width="42" Height="42" CornerRadius="10" Background="{DynamicResource Blue}">
            <TextBlock Text="LV" Foreground="{DynamicResource AccentInk}" FontWeight="Bold" FontSize="16"
                       HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Border>
          <StackPanel Margin="11,1,0,0" VerticalAlignment="Center">
            <TextBlock Text="LogVerdict" Foreground="{DynamicResource Text}" FontSize="17"
                       FontWeight="SemiBold"/>
            <TextBlock Text="Clarity from Windows logs" Foreground="{DynamicResource TextMuted}"
                       FontSize="10.5" Margin="0,2,0,0"/>
            <TextBlock x:Name="TxtVersion" Text="" Foreground="{DynamicResource TextMuted}"
                       FontSize="9.5" Margin="0,2,0,0"/>
          </StackPanel>
        </StackPanel>

        <StackPanel Grid.Row="1">
          <ToggleButton x:Name="NavOverview" Style="{StaticResource NavButton}" AutomationProperties.Name="Overview" IsChecked="True">
            <StackPanel Orientation="Horizontal">
              <Border Width="24" Height="24" CornerRadius="6" Background="{DynamicResource NavIconActive}">
                <TextBlock Text="O" HorizontalAlignment="Center" VerticalAlignment="Center"
                           Foreground="{DynamicResource Blue}" FontWeight="Bold" FontSize="11"/>
              </Border>
              <TextBlock Text="Overview" Margin="11,0,0,0" VerticalAlignment="Center"/>
            </StackPanel>
          </ToggleButton>
          <ToggleButton x:Name="NavFindings" Style="{StaticResource NavButton}" AutomationProperties.Name="Findings">
            <StackPanel Orientation="Horizontal">
              <Border Width="24" Height="24" CornerRadius="6" Background="{DynamicResource Surface0}">
                <TextBlock Text="F" HorizontalAlignment="Center" VerticalAlignment="Center"
                           Foreground="{DynamicResource Subtext0}" FontWeight="Bold" FontSize="11"/>
              </Border>
              <TextBlock Text="Findings" Margin="11,0,0,0" VerticalAlignment="Center"/>
            </StackPanel>
          </ToggleButton>
          <ToggleButton x:Name="NavCoverage" Style="{StaticResource NavButton}" AutomationProperties.Name="Coverage">
            <StackPanel Orientation="Horizontal">
              <Border Width="24" Height="24" CornerRadius="6" Background="{DynamicResource Surface0}">
                <TextBlock Text="C" HorizontalAlignment="Center" VerticalAlignment="Center"
                           Foreground="{DynamicResource Subtext0}" FontWeight="Bold" FontSize="11"/>
              </Border>
              <TextBlock Text="Coverage" Margin="11,0,0,0" VerticalAlignment="Center"/>
            </StackPanel>
          </ToggleButton>
          <ToggleButton x:Name="NavActivity" Style="{StaticResource NavButton}" AutomationProperties.Name="Activity">
            <StackPanel Orientation="Horizontal">
              <Border Width="24" Height="24" CornerRadius="6" Background="{DynamicResource Surface0}">
                <TextBlock Text="A" HorizontalAlignment="Center" VerticalAlignment="Center"
                           Foreground="{DynamicResource Subtext0}" FontWeight="Bold" FontSize="11"/>
              </Border>
              <TextBlock Text="Activity" Margin="11,0,0,0" VerticalAlignment="Center"/>
            </StackPanel>
          </ToggleButton>
        </StackPanel>

        <StackPanel Grid.Row="2" VerticalAlignment="Bottom" Margin="2,0,2,16">
          <TextBlock x:Name="TxtSideMachine" Text="" Foreground="{DynamicResource Subtext0}"
                     FontFamily="Consolas" FontSize="10.5" TextTrimming="CharacterEllipsis"/>
          <TextBlock x:Name="TxtSideElevation" Text="" Foreground="{DynamicResource TextMuted}"
                     FontSize="10.5" Margin="0,4,0,0"/>
          <Button x:Name="BtnSideElevate" Style="{StaticResource BaseButton}" Content="Request admin access"
                  Padding="9,6" Margin="0,10,0,0" HorizontalAlignment="Stretch" Visibility="Collapsed"/>
        </StackPanel>

        <Border Grid.Row="3" Style="{StaticResource Card}" Padding="12">
          <StackPanel>
            <StackPanel Orientation="Horizontal">
              <Border Width="22" Height="22" CornerRadius="11" BorderBrush="{DynamicResource Green}"
                      BorderThickness="1" Background="{DynamicResource SuccessPanel}">
                <TextBlock Text="+" Foreground="{DynamicResource Green}" FontWeight="Bold"
                           HorizontalAlignment="Center" VerticalAlignment="Center"/>
              </Border>
              <TextBlock x:Name="TxtSideDbTitle" Text="Database ready" Margin="9,1,0,0"
                         Foreground="{DynamicResource Text}" FontSize="11.5"/>
            </StackPanel>
            <TextBlock x:Name="TxtSideDbMeta" Text="Verdict rules bundled" Margin="31,2,0,0"
                       Foreground="{DynamicResource TextMuted}" FontSize="10.5"/>
            <Border Height="1" Background="{DynamicResource Surface1}" Margin="0,10,0,8"/>
            <TextBlock x:Name="TxtSideDbUpdated" Text="Updates shown after a scan"
                       Foreground="{DynamicResource TextMuted}" FontSize="10" TextAlignment="Center"/>
          </StackPanel>
        </Border>
      </Grid>
    </Border>

    <!-- ============ Elevation notice ============ -->
    <Border x:Name="PnlElevate" Grid.Column="1" Grid.Row="0" Background="{DynamicResource ElevationPanel}" BorderBrush="{DynamicResource Surface2}"
            BorderThickness="0,0,0,1" Padding="20,10" Visibility="Collapsed">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <TextBlock Grid.Column="0" VerticalAlignment="Center" TextWrapping="Wrap"
                   Foreground="{DynamicResource Subtext1}" FontSize="12"
                   Text="Running without administrator rights. The Security channel and some setup logs cannot be read, so a clean result here is not proof the machine is healthy."/>
        <Button x:Name="BtnElevate" Grid.Column="1" Style="{StaticResource BaseButton}"
                Margin="16,0,0,0" Content="Restart as administrator"/>
      </Grid>
    </Border>

    <!-- ============ Overview page ============ -->
    <Grid x:Name="PageOverview" Grid.Column="1" Grid.Row="1" Margin="22,18,22,16">
      <ScrollViewer VerticalScrollBarVisibility="Auto">
        <StackPanel>
          <Grid Margin="2,0,2,18">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <StackPanel>
              <TextBlock Text="System overview" Style="{StaticResource PageTitle}"/>
              <TextBlock Text="Scan this Windows device and turn noisy logs into clear next steps."
                         Style="{StaticResource PageSubtitle}"/>
            </StackPanel>
            <Border Grid.Column="1" CornerRadius="6" BorderBrush="{DynamicResource Surface2}"
                    BorderThickness="1" Background="{DynamicResource SoftPanel}" Padding="10,5" VerticalAlignment="Center">
              <TextBlock Text="Read-only - local only" Foreground="{DynamicResource Sky}" FontSize="11"/>
            </Border>
          </Grid>

          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="1.75*"/>
              <ColumnDefinition Width="1*"/>
            </Grid.ColumnDefinitions>

            <Border Grid.Column="0" Style="{StaticResource Card}" Margin="0,0,12,0">
              <StackPanel>
                <StackPanel Orientation="Horizontal">
                  <Border Width="38" Height="38" CornerRadius="9" Background="{DynamicResource StatusIcon}">
                    <TextBlock Text="~" Foreground="{DynamicResource Blue}" FontSize="22"
                               HorizontalAlignment="Center" VerticalAlignment="Center"/>
                  </Border>
                  <StackPanel Margin="12,0,0,0">
                    <TextBlock Text="Ready to scan" Foreground="{DynamicResource Text}" FontSize="17"
                               FontWeight="SemiBold"/>
                    <TextBlock Text="Read diagnostic sources on this device. Nothing is changed."
                               Foreground="{DynamicResource TextMuted}" FontSize="11.5" Margin="0,3,0,0"/>
                  </StackPanel>
                </StackPanel>

                <Grid Margin="0,14,0,0">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="150"/>
                    <ColumnDefinition Width="*"/>
                  </Grid.ColumnDefinitions>
                  <StackPanel Grid.Column="0" Margin="0,0,12,0">
                    <TextBlock Text="LOOK BACK" Style="{StaticResource PanelLabel}" Margin="0,0,0,6"/>
                    <TextBox x:Name="TxtOverviewDays" Text="30"
                             AutomationProperties.Name="Look back this many days"/>
                  </StackPanel>
                  <StackPanel Grid.Column="1">
                    <TextBlock Text="SOURCES" Style="{StaticResource PanelLabel}" Margin="0,0,0,6"/>
                    <WrapPanel>
                      <CheckBox x:Name="ChkOverviewAllChannels" Content="All event channels" Margin="0,0,20,6"/>
                      <CheckBox x:Name="ChkOverviewDiagnosticChannels" Content="Focused diagnostic channels" Margin="0,0,20,6"/>
                      <CheckBox x:Name="ChkOverviewIncludeText" Content="Include setup logs"
                                IsChecked="True" Margin="0,0,20,6"/>
                      <CheckBox x:Name="ChkOverviewIncludeBenign" Content="Show harmless" Margin="0,0,20,6"/>
                      <CheckBox x:Name="ChkOverviewIncludeLowConfidence" Content="Show low-confidence rulings" Margin="0,0,0,6"
                                ToolTip="Include curated low-confidence rulings for an explicit review pass."/>
                    </WrapPanel>
                  </StackPanel>
                </Grid>

                <TextBlock Text="ADVANCED SCAN" Style="{StaticResource PanelLabel}" Margin="0,12,0,6"/>
                <TextBlock Text="Named event channels" Foreground="{DynamicResource Subtext0}" FontSize="11"
                           Margin="0,0,0,4"/>
                <TextBox x:Name="TxtOverviewChannels" AutomationProperties.Name="Named event channels"
                         ToolTip="Comma, semicolon, or one channel per line. Named channels override the broader channel choices."/>

                <TextBlock Text="Alternate rule database" Foreground="{DynamicResource Subtext0}" FontSize="11"
                           Margin="0,8,0,4"/>
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <TextBox x:Name="TxtOverviewDatabase" AutomationProperties.Name="Alternate verdict database"
                           ToolTip="Optional path to a full verdicts.json database."/>
                  <Button x:Name="BtnOverviewBrowseDatabase" Grid.Column="1" Style="{StaticResource BaseButton}"
                          Content="Rules..." Margin="7,0,0,0" Padding="11,6"/>
                </Grid>
                <TextBlock Text="Suppression expectations" Foreground="{DynamicResource Subtext0}" FontSize="11"
                           Margin="0,8,0,4"/>
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <TextBox x:Name="TxtOverviewSuppression" AutomationProperties.Name="Suppression expectations"
                           ToolTip="Optional scoped expectations JSON. Matched findings remain counted and are marked suppressed."/>
                  <Button x:Name="BtnOverviewBrowseSuppression" Grid.Column="1" Style="{StaticResource BaseButton}"
                          Content="Expectations..." Margin="7,0,0,0" Padding="11,6"/>
                </Grid>
                <WrapPanel Margin="0,8,0,0">
                  <CheckBox x:Name="ChkOverviewSkipReliability" Content="Skip Reliability Monitor" Margin="0,0,20,6"/>
                </WrapPanel>

                <TextBlock Text="REPORT" Style="{StaticResource PanelLabel}" Margin="0,7,0,6"/>
                <TextBlock Text="Report folder" Foreground="{DynamicResource Subtext0}" FontSize="11"
                           Margin="0,0,0,4"/>
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <TextBox x:Name="TxtOverviewOutputDir" AutomationProperties.Name="Report folder"
                           ToolTip="Optional folder used by Save report."/>
                  <Button x:Name="BtnOverviewBrowseOutput" Grid.Column="1" Style="{StaticResource BaseButton}"
                          Content="Folder..." Margin="7,0,0,0" Padding="11,6"/>
                </Grid>
                <WrapPanel Margin="0,8,0,0">
                  <CheckBox x:Name="ChkOverviewRedact" Content="Redact reports and clipboard" Margin="0,0,20,6"/>
                  <CheckBox x:Name="ChkOverviewEvidence" Content="Include evidence zip (raw channels if unredacted)"
                            ToolTip="With redaction off, the evidence zip contains raw event-channel exports."
                            Margin="0,0,0,6"/>
                </WrapPanel>
                <StackPanel Orientation="Horizontal" Margin="0,2,0,0">
                  <Button x:Name="BtnResetSettings" Style="{StaticResource BaseButton}" Content="Reset settings"
                          AutomationProperties.Name="Reset saved settings"
                          ToolTip="Restore safe first-launch scan options and window size." Padding="11,6"/>
                  <TextBlock x:Name="TxtSettingsStatus" Margin="10,0,0,0" VerticalAlignment="Center"
                             Foreground="{DynamicResource TextMuted}" FontSize="10.5" TextWrapping="Wrap"/>
                </StackPanel>

                <StackPanel Orientation="Horizontal" Margin="0,13,0,0">
                  <Button x:Name="BtnOverviewScan" Style="{StaticResource AccentButton}" Content="Run scan"
                          Padding="18,9"/>
                  <Button x:Name="BtnOverviewCancel" Style="{StaticResource BaseButton}" Content="Cancel"
                          Margin="9,0,0,0" Visibility="Collapsed"/>
                  <TextBlock x:Name="TxtOverviewTimingHint" Text="Typical 30-day scan: 1-3 minutes. All-channel sweeps can take longer."
                             Margin="14,0,0,0" VerticalAlignment="Center"
                             Foreground="{DynamicResource TextMuted}" FontSize="11"/>
                </StackPanel>
              </StackPanel>
            </Border>

            <Border Grid.Column="1" Style="{StaticResource Card}" BorderBrush="{DynamicResource WarningBorder}" Background="{DynamicResource WarningCard}">
              <Grid>
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="*"/>
                  <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <StackPanel Orientation="Horizontal">
                  <Border Width="36" Height="36" CornerRadius="18" Background="{DynamicResource WarningIcon}"
                          BorderBrush="{DynamicResource Peach}" BorderThickness="1">
                    <TextBlock Text="!" Foreground="{DynamicResource Peach}" FontSize="18" FontWeight="Bold"
                               HorizontalAlignment="Center" VerticalAlignment="Center"/>
                  </Border>
                  <StackPanel Margin="11,0,0,0">
                    <TextBlock Text="Last scan" Foreground="{DynamicResource TextMuted}" FontSize="11"/>
                    <TextBlock x:Name="TxtOverviewLastVerdict" Text="No scan yet"
                               Foreground="{DynamicResource Text}" FontSize="17" FontWeight="SemiBold"/>
                  </StackPanel>
                </StackPanel>
                <StackPanel Grid.Row="1" VerticalAlignment="Center" Margin="47,8,0,8">
                  <TextBlock x:Name="TxtOverviewFindingCount" Text="-" Style="{StaticResource MetricValue}" FontSize="34"/>
                  <TextBlock Text="findings" Foreground="{DynamicResource TextMuted}"/>
                </StackPanel>
                <TextBlock x:Name="TxtOverviewScanTime" Grid.Row="2" Text="Run a scan to establish a baseline"
                           Foreground="{DynamicResource TextMuted}" FontSize="10.5"/>
              </Grid>
            </Border>
          </Grid>

          <StackPanel x:Name="PnlOverviewSummary" Visibility="Collapsed" Margin="0,12,0,0">
            <Grid>
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
              </Grid.ColumnDefinitions>
              <Border Grid.Column="0" Style="{StaticResource Card}" Padding="14" Margin="0,0,8,0">
                <StackPanel><TextBlock x:Name="TxtOverviewRecords" Style="{StaticResource MetricValue}" Text="-"/>
                  <TextBlock Text="Records read" Foreground="{DynamicResource Subtext0}"/>
                  <TextBlock Text="Windows diagnostic entries" Foreground="{DynamicResource TextMuted}" FontSize="10" Margin="0,3,0,0"/></StackPanel>
              </Border>
              <Border Grid.Column="1" Style="{StaticResource Card}" Padding="14" Margin="0,0,8,0">
                <StackPanel><TextBlock x:Name="TxtOverviewSignatures" Style="{StaticResource MetricValue}" Text="-"/>
                  <TextBlock Text="Signatures" Foreground="{DynamicResource Subtext0}"/>
                  <TextBlock Text="Distinct patterns" Foreground="{DynamicResource TextMuted}" FontSize="10" Margin="0,3,0,0"/></StackPanel>
              </Border>
              <Border Grid.Column="2" Style="{StaticResource Card}" Padding="14" Margin="0,0,8,0">
                <StackPanel><TextBlock x:Name="TxtOverviewReduction" Style="{StaticResource MetricValue}" Foreground="{DynamicResource Sky}" Text="-"/>
                  <TextBlock Text="Noise removed" Foreground="{DynamicResource Subtext0}"/>
                  <TextBlock Text="Lower signal, clearer result" Foreground="{DynamicResource TextMuted}" FontSize="10" Margin="0,3,0,0"/></StackPanel>
              </Border>
              <Border Grid.Column="3" Style="{StaticResource Card}" Padding="14">
                <StackPanel><TextBlock x:Name="TxtOverviewRules" Style="{StaticResource MetricValue}" Text="-"/>
                  <TextBlock Text="Rules applied" Foreground="{DynamicResource Subtext0}"/>
                  <TextBlock Text="Curated rulings" Foreground="{DynamicResource TextMuted}" FontSize="10" Margin="0,3,0,0"/></StackPanel>
              </Border>
            </Grid>

            <Border Style="{StaticResource Card}" Padding="14,11" Margin="0,10,0,0">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="*"/><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0"><TextBlock Text="CRITICAL" Foreground="{DynamicResource TextMuted}" FontSize="9.5"/><TextBlock x:Name="TxtOverviewCritical" Text="0" FontSize="20" Foreground="{DynamicResource Red}"/></StackPanel>
                <StackPanel Grid.Column="1"><TextBlock Text="ACTIONABLE" Foreground="{DynamicResource TextMuted}" FontSize="9.5"/><TextBlock x:Name="TxtOverviewActionable" Text="0" FontSize="20" Foreground="{DynamicResource Peach}"/></StackPanel>
                <StackPanel Grid.Column="2"><TextBlock Text="INVESTIGATE" Foreground="{DynamicResource TextMuted}" FontSize="9.5"/><TextBlock x:Name="TxtOverviewInvestigate" Text="0" FontSize="20" Foreground="{DynamicResource Yellow}"/></StackPanel>
                <StackPanel Grid.Column="3"><TextBlock Text="UNKNOWN" Foreground="{DynamicResource TextMuted}" FontSize="9.5"/><TextBlock x:Name="TxtOverviewUnknown" Text="0" FontSize="20" Foreground="{DynamicResource Lavender}"/></StackPanel>
                <StackPanel Grid.Column="4"><TextBlock Text="INFO" Foreground="{DynamicResource TextMuted}" FontSize="9.5"/><TextBlock x:Name="TxtOverviewInfo" Text="0" FontSize="20" Foreground="{DynamicResource Sky}"/></StackPanel>
                <StackPanel Grid.Column="5"><TextBlock Text="HARMLESS" Foreground="{DynamicResource TextMuted}" FontSize="9.5"/><TextBlock x:Name="TxtOverviewBenign" Text="0" FontSize="20" Foreground="{DynamicResource Green}"/></StackPanel>
              </Grid>
            </Border>

            <Grid Margin="0,10,0,0">
              <Grid.ColumnDefinitions><ColumnDefinition Width="1.65*"/><ColumnDefinition Width="1*"/></Grid.ColumnDefinitions>
              <Border Grid.Column="0" Style="{StaticResource Card}" Padding="0" Margin="0,0,10,0">
                <Grid>
                  <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                  <Grid Grid.Row="0" Margin="14,11,14,7">
                    <TextBlock Text="Priority findings" Foreground="{DynamicResource Text}" FontWeight="SemiBold"/>
                    <Button x:Name="BtnViewFindings" Style="{StaticResource BaseButton}" Content="View all findings"
                            HorizontalAlignment="Right" Background="Transparent" BorderBrush="Transparent" Padding="7,3"
                            Foreground="{DynamicResource Blue}" FontSize="10.5"/>
                  </Grid>
                  <ListView x:Name="LvPriority" Grid.Row="1" Background="Transparent" BorderThickness="0"
                            MaxHeight="132" ItemContainerStyle="{StaticResource FindingRow}"
                            ScrollViewer.HorizontalScrollBarVisibility="Disabled"
                            ScrollViewer.CanContentScroll="True"
                            VirtualizingPanel.IsVirtualizing="True"
                            VirtualizingPanel.VirtualizationMode="Recycling">
                    <ListView.View><GridView AllowsColumnReorder="False">
                      <GridViewColumn Header="VERDICT" Width="105">
                        <GridViewColumn.CellTemplate><DataTemplate><Border CornerRadius="4" Padding="6,2" Background="{Binding VerdictFill}" HorizontalAlignment="Left"><TextBlock Text="{Binding VerdictLabel}" Foreground="{Binding VerdictInk}" FontSize="9.5" FontWeight="SemiBold"/></Border></DataTemplate></GridViewColumn.CellTemplate>
                      </GridViewColumn>
                      <GridViewColumn Header="WHAT HAPPENED" Width="410" DisplayMemberBinding="{Binding Title}"/>
                      <GridViewColumn Header="COUNT" Width="70" DisplayMemberBinding="{Binding Count}"/>
                      <GridViewColumn Header="LATEST" Width="115" DisplayMemberBinding="{Binding LastSeenText}"/>
                    </GridView></ListView.View>
                  </ListView>
                </Grid>
              </Border>
              <Border Grid.Column="1" Style="{StaticResource Card}">
                <StackPanel>
                  <StackPanel Orientation="Horizontal">
                    <Border Width="32" Height="32" CornerRadius="16" BorderBrush="{DynamicResource Sky}" BorderThickness="1" Background="{DynamicResource InfoPanel}"><TextBlock Text="C" Foreground="{DynamicResource Sky}" HorizontalAlignment="Center" VerticalAlignment="Center" FontWeight="Bold"/></Border>
                    <StackPanel Margin="11,0,0,0"><TextBlock Text="Coverage confidence" Foreground="{DynamicResource Text}" FontWeight="SemiBold"/><TextBlock Text="Latest scan trust context" Foreground="{DynamicResource TextMuted}" FontSize="10.5" Margin="0,2,0,0"/></StackPanel>
                  </StackPanel>
                  <TextBlock x:Name="TxtOverviewCoverage" Text="Coverage details appear after the first scan."
                             TextWrapping="Wrap" Foreground="{DynamicResource Subtext0}" Margin="0,13,0,0" LineHeight="18"/>
                  <Button x:Name="BtnViewCoverage" Style="{StaticResource BaseButton}" Content="Review coverage"
                          Foreground="{DynamicResource Blue}" HorizontalAlignment="Left" Margin="0,11,0,0" Padding="8,5"/>
                </StackPanel>
              </Border>
            </Grid>
          </StackPanel>
        </StackPanel>
      </ScrollViewer>
    </Grid>

    <!-- ============ Body ============ -->
    <Grid x:Name="PageFindings" Grid.Column="1" Grid.Row="1" Visibility="Collapsed">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*" MinWidth="380"/>
        <ColumnDefinition Width="5"/>
        <ColumnDefinition Width="450" MinWidth="330"/>
      </Grid.ColumnDefinitions>

      <!-- ==== Centre: findings ==== -->
      <Grid Grid.Column="0">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <Grid Grid.Row="0" Margin="22,18,16,10">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <StackPanel>
            <TextBlock Text="Findings" Style="{StaticResource PageTitle}"/>
            <TextBlock Text="Signatures from the latest scan, worst first"
                       Style="{StaticResource PageSubtitle}"/>
          </StackPanel>
          <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
            <Button x:Name="BtnFindingsSave" Style="{StaticResource BaseButton}" Content="Save report" Padding="10,6"/>
            <Button x:Name="BtnFindingsOpen" Style="{StaticResource BaseButton}" Content="Open report"
                    Padding="10,6" Margin="8,0,0,0"/>
          </StackPanel>
        </Grid>

        <Grid Grid.Row="1" Margin="22,0,16,10">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <!-- Name, not LabeledBy: the only caption is the placeholder, which vanishes
               as soon as the box has text, and a name that disappears is worse than none. -->
          <TextBox x:Name="TxtSearch" Grid.Column="0"
                   AutomationProperties.Name="Filter findings by title, provider, event id or message"/>
          <TextBlock x:Name="TxtSearchHint" Grid.Column="0" IsHitTestVisible="False"
                     Margin="10,0,0,0" VerticalAlignment="Center"
                     Foreground="{DynamicResource TextMuted}" FontSize="12.5"
                     Text="Filter by title, provider, event id or message"/>
          <TextBlock x:Name="TxtShown" Grid.Column="1" Margin="14,0,0,0" VerticalAlignment="Center"
                     Foreground="{DynamicResource TextMuted}" FontSize="11.5" Text=""/>
        </Grid>

        <UniformGrid Grid.Row="2" Columns="6" Margin="22,0,16,9">
          <ToggleButton x:Name="FltCritical" Style="{StaticResource ChipToggle}" Tag="{DynamicResource Red}" IsChecked="True" Margin="0,0,6,0" FontSize="10.5"/>
          <ToggleButton x:Name="FltActionable" Style="{StaticResource ChipToggle}" Tag="{DynamicResource Peach}" IsChecked="True" Margin="0,0,6,0" FontSize="10.5"/>
          <ToggleButton x:Name="FltInvestigate" Style="{StaticResource ChipToggle}" Tag="{DynamicResource Yellow}" IsChecked="True" Margin="0,0,6,0" FontSize="10.5"/>
          <ToggleButton x:Name="FltUnknown" Style="{StaticResource ChipToggle}" Tag="{DynamicResource Lavender}" IsChecked="True" Margin="0,0,6,0" FontSize="10.5"/>
          <ToggleButton x:Name="FltInformational" Style="{StaticResource ChipToggle}" Tag="{DynamicResource Sky}" IsChecked="True" Margin="0,0,6,0" FontSize="10.5"/>
          <ToggleButton x:Name="FltBenign" Style="{StaticResource ChipToggle}" Tag="{DynamicResource Green}" IsChecked="True" Margin="0" FontSize="10.5"/>
        </UniformGrid>

        <UniformGrid Grid.Row="3" Columns="6" Margin="22,0,16,10">
          <StackPanel Margin="0,0,6,0">
            <TextBlock Text="SOURCE" Style="{StaticResource PanelLabel}" Margin="0,0,0,4"/>
            <ComboBox x:Name="FltSource" Style="{StaticResource FilterCombo}" DisplayMemberPath="Label"
                      SelectedValuePath="Value" AutomationProperties.Name="Filter findings by source"/>
          </StackPanel>
          <StackPanel Margin="0,0,6,0">
            <TextBlock Text="CHANNEL" Style="{StaticResource PanelLabel}" Margin="0,0,0,4"/>
            <ComboBox x:Name="FltChannel" Style="{StaticResource FilterCombo}" DisplayMemberPath="Label"
                      SelectedValuePath="Value" AutomationProperties.Name="Filter findings by channel"/>
          </StackPanel>
          <StackPanel Margin="0,0,6,0">
            <TextBlock Text="PROVIDER" Style="{StaticResource PanelLabel}" Margin="0,0,0,4"/>
            <ComboBox x:Name="FltProvider" Style="{StaticResource FilterCombo}" DisplayMemberPath="Label"
                      SelectedValuePath="Value" AutomationProperties.Name="Filter findings by provider"/>
          </StackPanel>
          <StackPanel Margin="0,0,6,0">
            <TextBlock Text="EVENT ID" Style="{StaticResource PanelLabel}" Margin="0,0,0,4"/>
            <ComboBox x:Name="FltEventId" Style="{StaticResource FilterCombo}" DisplayMemberPath="Label"
                      SelectedValuePath="Value" AutomationProperties.Name="Filter findings by event ID"/>
          </StackPanel>
          <StackPanel Margin="0,0,6,0">
            <TextBlock Text="CORRELATION" Style="{StaticResource PanelLabel}" Margin="0,0,0,4"/>
            <ComboBox x:Name="FltCorrelation" Style="{StaticResource FilterCombo}" DisplayMemberPath="Label"
                      SelectedValuePath="Value" AutomationProperties.Name="Filter findings by correlation"/>
          </StackPanel>
          <StackPanel>
            <TextBlock Text="RULE STATE" Style="{StaticResource PanelLabel}" Margin="0,0,0,4"/>
            <ComboBox x:Name="FltRuleStatus" Style="{StaticResource FilterCombo}" DisplayMemberPath="Label"
                      SelectedValuePath="Value" AutomationProperties.Name="Filter findings by rule status"/>
          </StackPanel>
        </UniformGrid>

        <ListView x:Name="LvFindings" Grid.Row="4" Background="Transparent" BorderThickness="0"
                  Margin="22,0,16,14"
                  AutomationProperties.Name="Findings, worst first"
                  ItemContainerStyle="{StaticResource FindingRow}"
                  ScrollViewer.HorizontalScrollBarVisibility="Disabled"
                  ScrollViewer.CanContentScroll="True"
                  VirtualizingPanel.IsVirtualizing="True"
                  VirtualizingPanel.VirtualizationMode="Recycling"
                  VirtualizingPanel.ScrollUnit="Pixel">
          <ListView.View>
            <GridView AllowsColumnReorder="False">
              <GridViewColumn Header="VERDICT" Width="102">
                <GridViewColumn.CellTemplate>
                  <DataTemplate>
                    <Border CornerRadius="4" Padding="7,2.5" HorizontalAlignment="Left"
                            Background="{Binding VerdictFill}">
                      <TextBlock Text="{Binding VerdictLabel}" FontSize="10.5" FontWeight="SemiBold"
                                 Foreground="{Binding VerdictInk}"/>
                    </Border>
                  </DataTemplate>
                </GridViewColumn.CellTemplate>
              </GridViewColumn>
              <GridViewColumn Header="WHAT HAPPENED" Width="300">
                <GridViewColumn.CellTemplate>
                  <DataTemplate>
                    <TextBlock Text="{Binding Title}" TextTrimming="CharacterEllipsis"
                               ToolTip="{Binding Title}" Margin="0,0,10,0"/>
                  </DataTemplate>
                </GridViewColumn.CellTemplate>
              </GridViewColumn>
              <GridViewColumn Header="TIMES" Width="58">
                <GridViewColumn.CellTemplate>
                  <DataTemplate>
                    <TextBlock Text="{Binding Count}" HorizontalAlignment="Right" Margin="0,0,16,0"/>
                  </DataTemplate>
                </GridViewColumn.CellTemplate>
              </GridViewColumn>
              <GridViewColumn Header="PER DAY" Width="70">
                <GridViewColumn.CellTemplate>
                  <DataTemplate>
                    <TextBlock Text="{Binding PerDayText}" HorizontalAlignment="Right" Margin="0,0,16,0"
                               Foreground="{DynamicResource Subtext0}"/>
                  </DataTemplate>
                </GridViewColumn.CellTemplate>
              </GridViewColumn>
              <GridViewColumn Header="LAST SEEN" Width="118">
                <GridViewColumn.CellTemplate>
                  <DataTemplate>
                    <TextBlock Text="{Binding LastSeenText}" Foreground="{DynamicResource Subtext0}"/>
                  </DataTemplate>
                </GridViewColumn.CellTemplate>
              </GridViewColumn>
            </GridView>
          </ListView.View>
        </ListView>

        <!-- Shown before the first scan and whenever the filter empties the list. -->
        <StackPanel x:Name="PnlEmpty" Grid.Row="4" VerticalAlignment="Center"
                    HorizontalAlignment="Center" Margin="30">
          <TextBlock x:Name="TxtEmptyTitle" HorizontalAlignment="Center" FontSize="15"
                     Foreground="{DynamicResource Subtext0}" Text="Nothing scanned yet"/>
          <TextBlock x:Name="TxtEmptyBody" HorizontalAlignment="Center" Margin="0,7,0,0"
                     MaxWidth="420" TextAlignment="Center" TextWrapping="Wrap" LineHeight="19"
                     Foreground="{DynamicResource TextMuted}" FontSize="12.5"
                     Text="Press Run scan. LogVerdict reads this machine's event channels and setup logs, collapses the repeats, and rules on what is left. Nothing is modified."/>
        </StackPanel>
      </Grid>

      <GridSplitter Grid.Column="1" HorizontalAlignment="Stretch" VerticalAlignment="Stretch"/>

      <!-- ==== Right: detail ==== -->
      <Border Grid.Column="2" Background="{DynamicResource Mantle}" BorderBrush="{DynamicResource Surface0}"
              BorderThickness="1,0,0,0">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>

          <TextBlock x:Name="TxtNoSelection" Grid.Row="0" VerticalAlignment="Center"
                     HorizontalAlignment="Center" Margin="30" TextAlignment="Center"
                     TextWrapping="Wrap" Foreground="{DynamicResource TextMuted}" FontSize="12.5"
                     Text="Select a finding to see what it means and what to do about it."/>

          <ScrollViewer x:Name="ScrDetail" Grid.Row="0" VerticalScrollBarVisibility="Auto"
                        Visibility="Collapsed" Padding="20,18,14,18">
            <StackPanel>
              <Border x:Name="PillDetail" CornerRadius="4" Padding="8,3" HorizontalAlignment="Left"
                      Background="{DynamicResource Surface0}">
                <TextBlock x:Name="TxtDetailVerdict" FontSize="10.5" FontWeight="SemiBold" Text=""/>
              </Border>

              <TextBlock x:Name="TxtDetailTitle" Margin="0,11,0,0" FontSize="16" FontWeight="SemiBold"
                         TextWrapping="Wrap" LineHeight="22" Foreground="{DynamicResource Text}" Text=""/>
              <TextBlock x:Name="TxtDetailMeta" Margin="0,7,0,0" FontSize="11.5" TextWrapping="Wrap"
                         Foreground="{DynamicResource TextMuted}" FontFamily="Consolas" Text=""/>

              <TextBlock Text="IN PLAIN ENGLISH" Style="{StaticResource SectionLabel}"/>
              <TextBlock x:Name="TxtPlain" Style="{StaticResource BodyText}" Text=""/>

              <TextBlock Text="WHY THIS RULING" Style="{StaticResource SectionLabel}"/>
              <TextBlock x:Name="TxtWhy" Style="{StaticResource BodyText}" Text=""/>

              <TextBlock Text="WHAT TO DO" Style="{StaticResource SectionLabel}"/>
              <Border Background="{DynamicResource Base}" CornerRadius="6" Padding="12,10"
                      BorderBrush="{DynamicResource Surface0}" BorderThickness="1">
                <TextBlock x:Name="TxtAction" Style="{StaticResource BodyText}"
                           Foreground="{DynamicResource Text}" Text=""/>
              </Border>

              <StackPanel x:Name="PnlFalsePositives" Visibility="Collapsed">
                <TextBlock Text="COULD ALSO BE INNOCENT WHEN" Style="{StaticResource SectionLabel}"/>
                <ItemsControl x:Name="LstFalsePositives">
                  <ItemsControl.ItemTemplate>
                    <DataTemplate>
                      <TextBlock Text="{Binding}" TextWrapping="Wrap" Margin="0,0,0,5"
                                 Foreground="{DynamicResource Subtext0}" FontSize="12" LineHeight="18"/>
                    </DataTemplate>
                  </ItemsControl.ItemTemplate>
                </ItemsControl>
              </StackPanel>

              <StackPanel x:Name="PnlRefs" Visibility="Collapsed">
                <TextBlock Text="SOURCES" Style="{StaticResource SectionLabel}"/>
                <ItemsControl x:Name="LstRefs">
                  <ItemsControl.ItemTemplate>
                    <DataTemplate>
                      <TextBlock TextWrapping="Wrap" Margin="0,0,0,5" FontSize="11.5">
                        <Hyperlink NavigateUri="{Binding}" Foreground="{DynamicResource Blue}"
                                   TextDecorations="Underline">
                          <TextBlock Text="{Binding}" TextWrapping="Wrap"/>
                        </Hyperlink>
                      </TextBlock>
                    </DataTemplate>
                  </ItemsControl.ItemTemplate>
                </ItemsControl>
                <ItemsControl x:Name="LstUnsafeRefs" Margin="0,4,0,0">
                  <ItemsControl.ItemTemplate>
                    <DataTemplate>
                      <TextBlock Text="{Binding}" TextWrapping="Wrap" Margin="0,0,0,5" FontSize="11.5"
                                 Foreground="{DynamicResource Peach}"/>
                    </DataTemplate>
                  </ItemsControl.ItemTemplate>
                </ItemsControl>
              </StackPanel>

              <TextBlock Text="RAW EVIDENCE, UNEDITED" Style="{StaticResource SectionLabel}"/>
              <Border Background="{DynamicResource Crust}" CornerRadius="6" Padding="12,10"
                      BorderBrush="{DynamicResource Surface0}" BorderThickness="1">
                <TextBox x:Name="TxtSample" IsReadOnly="True" TextWrapping="Wrap"
                         AutomationProperties.Name="Raw evidence for the selected finding"
                         Background="Transparent" BorderThickness="0" Padding="0"
                         FontFamily="Consolas" FontSize="11.5"
                         Foreground="{DynamicResource Subtext0}"
                         MaxHeight="260" VerticalScrollBarVisibility="Auto" Text=""/>
              </Border>

              <TextBlock x:Name="TxtProvenance" Margin="0,14,0,0" FontSize="11" TextWrapping="Wrap"
                         Foreground="{DynamicResource TextMuted}" LineHeight="16" Text=""/>
            </StackPanel>
          </ScrollViewer>

          <Border Grid.Row="1" Background="{DynamicResource Crust}" BorderBrush="{DynamicResource Surface0}"
                  BorderThickness="0,1,0,0" Padding="14,11">
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
              <Button x:Name="BtnCopy" Style="{StaticResource BaseButton}" Content="Copy finding"
                      Padding="11,6" IsEnabled="False"/>
              <Button x:Name="BtnCopySummary" Style="{StaticResource BaseButton}" Margin="8,0,0,0"
                      Content="Copy summary for ticket" Padding="11,6" IsEnabled="False"/>
              <Button x:Name="BtnSaveReport" Style="{StaticResource BaseButton}" Margin="8,0,0,0"
                      Content="Save report" Padding="11,6" IsEnabled="False"/>
              <Button x:Name="BtnOpenReport" Style="{StaticResource BaseButton}" Margin="8,0,0,0"
                      Content="Open report" Padding="11,6" IsEnabled="False"/>
            </StackPanel>
          </Border>
        </Grid>
      </Border>
    </Grid>

    <!-- ============ Coverage page ============ -->
    <Grid x:Name="PageCoverage" Grid.Column="1" Grid.Row="1" Visibility="Collapsed" Margin="22,18,22,16">
      <ScrollViewer VerticalScrollBarVisibility="Auto">
        <StackPanel>
          <Grid Margin="2,0,2,16">
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
            <StackPanel>
              <TextBlock Text="Coverage" Style="{StaticResource PageTitle}"/>
              <TextBlock Text="What the latest scan could and could not see" Style="{StaticResource PageSubtitle}"/>
            </StackPanel>
            <Button x:Name="BtnCoverageElevate" Grid.Column="1" Style="{StaticResource BaseButton}"
                    Content="Request admin access" Padding="11,7" VerticalAlignment="Center"/>
          </Grid>

          <Border Style="{StaticResource Card}" BorderBrush="{DynamicResource WarningBorder}" Background="{DynamicResource CoveragePanel}" Padding="16,13">
            <Grid>
              <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="270"/></Grid.ColumnDefinitions>
              <Border Width="38" Height="38" CornerRadius="19" Background="{DynamicResource WarningIcon}"
                      BorderBrush="{DynamicResource Peach}" BorderThickness="1">
                <TextBlock Text="!" Foreground="{DynamicResource Peach}" FontSize="18" FontWeight="Bold"
                           HorizontalAlignment="Center" VerticalAlignment="Center"/>
              </Border>
              <StackPanel Grid.Column="1" Margin="13,0,18,0">
                <TextBlock x:Name="TxtCoverageState" Text="No coverage baseline" Foreground="{DynamicResource Text}"
                           FontSize="16" FontWeight="SemiBold"/>
                <TextBlock x:Name="TxtCoverageSummary" Text="Run a scan to measure readable diagnostic sources."
                           Foreground="{DynamicResource Subtext0}" FontSize="11.5" TextWrapping="Wrap" Margin="0,3,0,0"/>
              </StackPanel>
              <StackPanel Grid.Column="2" VerticalAlignment="Center">
                <TextBlock x:Name="TxtCoverageRatio" Text="Waiting for first scan" Foreground="{DynamicResource Subtext0}" FontSize="11"/>
                <ProgressBar x:Name="PbCoverage" Value="0" Maximum="100" Height="6" Margin="0,7,0,0"/>
              </StackPanel>
            </Grid>
          </Border>

          <Grid Margin="0,10,0,0">
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <Border Grid.Column="0" Style="{StaticResource Card}" Padding="14" Margin="0,0,8,0">
              <StackPanel><TextBlock x:Name="TxtCoverageReadable" Style="{StaticResource MetricValue}" Text="-"/><TextBlock Text="Sources readable" Foreground="{DynamicResource Subtext0}"/></StackPanel>
            </Border>
            <Border Grid.Column="1" Style="{StaticResource Card}" Padding="14" Margin="0,0,8,0">
              <StackPanel><TextBlock x:Name="TxtCoverageGaps" Style="{StaticResource MetricValue}" Foreground="{DynamicResource Peach}" Text="-"/><TextBlock Text="Coverage notes" Foreground="{DynamicResource Subtext0}"/></StackPanel>
            </Border>
            <Border Grid.Column="2" Style="{StaticResource Card}" Padding="14">
              <StackPanel><TextBlock x:Name="TxtCoverageWindow" Style="{StaticResource MetricValue}" Text="-"/><TextBlock Text="Requested window" Foreground="{DynamicResource Subtext0}"/></StackPanel>
            </Border>
          </Grid>

          <Grid Margin="0,10,0,0">
            <Grid.ColumnDefinitions><ColumnDefinition Width="1.55*"/><ColumnDefinition Width="1*"/></Grid.ColumnDefinitions>
            <Border Grid.Column="0" Style="{StaticResource Card}" Margin="0,0,10,0" Padding="0">
              <Grid>
                <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                <Grid Grid.Row="0" Margin="15,12,15,9">
                  <TextBlock Text="Source coverage" Foreground="{DynamicResource Text}" FontSize="14" FontWeight="SemiBold"/>
                  <TextBlock Text="OLDEST RECORD / AVAILABILITY" HorizontalAlignment="Right" Foreground="{DynamicResource TextMuted}" FontSize="9.5"/>
                </Grid>
                <ItemsControl x:Name="LstChannelCoverage" Grid.Row="1" Margin="0,0,0,7">
                  <ItemsControl.ItemTemplate>
                    <DataTemplate>
                      <Border BorderBrush="{DynamicResource Surface0}" BorderThickness="0,1,0,0" Padding="15,7">
                        <TextBlock Text="{Binding}" Foreground="{DynamicResource Subtext0}" FontFamily="Consolas"
                                   FontSize="10.5" TextTrimming="CharacterEllipsis"/>
                      </Border>
                    </DataTemplate>
                  </ItemsControl.ItemTemplate>
                </ItemsControl>
              </Grid>
            </Border>

            <StackPanel Grid.Column="1">
              <Border Style="{StaticResource Card}" Padding="14">
                <StackPanel>
                  <TextBlock Text="Rule freshness" Foreground="{DynamicResource Text}" FontSize="14" FontWeight="SemiBold"/>
                  <TextBlock x:Name="TxtCoverageStaleSummary" Text="Freshness status appears after the first scan."
                             TextWrapping="Wrap" Foreground="{DynamicResource Subtext0}" FontSize="10.5" Margin="0,5,0,0" LineHeight="16"/>
                  <ItemsControl x:Name="LstStaleRulesPage" Margin="0,6,0,0">
                    <ItemsControl.ItemTemplate><DataTemplate><Border BorderBrush="{DynamicResource Surface0}" BorderThickness="0,1,0,0" Padding="0,6"><TextBlock Text="{Binding}" TextWrapping="Wrap" Foreground="{DynamicResource Subtext0}" FontFamily="Consolas" FontSize="10"/></Border></DataTemplate></ItemsControl.ItemTemplate>
                  </ItemsControl>
                  <TextBlock x:Name="TxtStaleNone" Text="No active rule is past its freshness threshold." Foreground="{DynamicResource Green}" FontSize="10.5" Margin="0,8,0,0"/>
                </StackPanel>
              </Border>
              <Border Style="{StaticResource Card}" Padding="14">
                <StackPanel>
                  <TextBlock Text="Coverage gaps" Foreground="{DynamicResource Text}" FontSize="14" FontWeight="SemiBold"/>
                  <ItemsControl x:Name="LstCoveragePage" Margin="0,8,0,0">
                    <ItemsControl.ItemTemplate><DataTemplate><Border BorderBrush="{DynamicResource Surface0}" BorderThickness="0,1,0,0" Padding="0,7"><TextBlock Text="{Binding}" TextWrapping="Wrap" Foreground="{DynamicResource Subtext0}" FontSize="10.5" LineHeight="16"/></Border></DataTemplate></ItemsControl.ItemTemplate>
                  </ItemsControl>
                  <TextBlock x:Name="TxtCoverageNone" Text="No coverage gaps were reported." Foreground="{DynamicResource Green}" FontSize="11" Margin="0,10,0,0"/>
                  <Border Height="1" Background="{DynamicResource Surface0}" Margin="0,10,0,9"/>
                  <TextBlock Text="Event horizon" Foreground="{DynamicResource Text}" FontSize="12" FontWeight="SemiBold"/>
                  <TextBlock x:Name="TxtHorizonPage" Text="History depth appears after the first scan."
                             TextWrapping="Wrap" Foreground="{DynamicResource Subtext0}" FontSize="10.5" Margin="0,5,0,0" LineHeight="16"/>
                </StackPanel>
              </Border>

              <Border Style="{StaticResource Card}" Padding="14" Margin="0,9,0,0">
                <StackPanel>
                  <TextBlock Text="Crash evidence on disk" Foreground="{DynamicResource Text}" FontSize="14" FontWeight="SemiBold"/>
                  <ItemsControl x:Name="LstCrashPage" Margin="0,7,0,0">
                    <ItemsControl.ItemTemplate><DataTemplate><TextBlock Text="{Binding}" TextWrapping="Wrap" Foreground="{DynamicResource TextMuted}" FontFamily="Consolas" FontSize="10" Margin="0,0,0,4"/></DataTemplate></ItemsControl.ItemTemplate>
                  </ItemsControl>
                  <TextBlock x:Name="TxtCrashNone" Text="No crash artifacts were collected." Foreground="{DynamicResource TextMuted}" FontSize="10.5" Margin="0,7,0,0"/>
                </StackPanel>
              </Border>
            </StackPanel>
          </Grid>

          <Border Style="{StaticResource Card}" Padding="15,12" Margin="0,10,0,0">
            <StackPanel>
              <TextBlock Text="Signatures that happened together" Foreground="{DynamicResource Text}" FontSize="14" FontWeight="SemiBold"/>
              <TextBlock Text="Apart they are symptoms; together they can name a cause."
                         Foreground="{DynamicResource TextMuted}" FontSize="10.5" Margin="0,3,0,0"/>
              <ItemsControl x:Name="LstCorrelationPage" Margin="0,8,0,0">
                <ItemsControl.ItemTemplate><DataTemplate><Border Background="{DynamicResource RowHover}" CornerRadius="6" Padding="11,8" Margin="0,0,0,5"><TextBlock Text="{Binding}" TextWrapping="Wrap" Foreground="{DynamicResource Subtext1}" FontSize="11"/></Border></DataTemplate></ItemsControl.ItemTemplate>
              </ItemsControl>
              <TextBlock x:Name="TxtCorrelationNone" Text="No curated correlations fired in the latest scan."
                         Foreground="{DynamicResource TextMuted}" FontSize="10.5" Margin="0,6,0,0"/>
            </StackPanel>
          </Border>
        </StackPanel>
      </ScrollViewer>
    </Grid>

    <!-- ============ Activity page ============ -->
    <Grid x:Name="PageActivity" Grid.Column="1" Grid.Row="1" Visibility="Collapsed" Margin="22,18,22,16">
      <Grid>
        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
        <Grid Grid.Row="0" Margin="2,0,2,16">
          <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
          <StackPanel>
            <TextBlock Text="Activity" Style="{StaticResource PageTitle}"/>
            <TextBlock x:Name="TxtActivitySubtitle" Text="No scan has run in this session" Style="{StaticResource PageSubtitle}"/>
          </StackPanel>
          <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
            <Border CornerRadius="6" BorderBrush="{DynamicResource Surface2}" BorderThickness="1"
                    Background="{DynamicResource SoftPanel}" Padding="10,6">
              <TextBlock x:Name="TxtActivityState" Text="Ready" Foreground="{DynamicResource Sky}" FontSize="11"/>
            </Border>
            <Button x:Name="BtnActivityClear" Style="{StaticResource BaseButton}" Content="Clear view"
                    Margin="8,0,0,0" Padding="10,6"/>
          </StackPanel>
        </Grid>

        <Border Grid.Row="1" Style="{StaticResource Card}" Padding="18,13" Margin="0,0,0,10">
          <Grid>
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
            <Grid>
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/>
              </Grid.ColumnDefinitions>
              <Border Grid.ColumnSpan="5" Height="2" Background="{DynamicResource SuccessLine}" Margin="95,0,95,20" VerticalAlignment="Center"/>
              <StackPanel Grid.Column="0" HorizontalAlignment="Center"><Border Width="28" Height="28" CornerRadius="14" Background="{DynamicResource SuccessIcon}" BorderBrush="{DynamicResource Green}" BorderThickness="1"><Path Data="M 1,5 L 4,8 L 10,1" Stroke="{DynamicResource Green}" StrokeThickness="2" StrokeStartLineCap="Round" StrokeEndLineCap="Round" Width="11" Height="9" Stretch="Fill" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><TextBlock Text="Collect" Foreground="{DynamicResource Subtext0}" Margin="0,4,0,0"/></StackPanel>
              <StackPanel Grid.Column="1" HorizontalAlignment="Center"><Border Width="28" Height="28" CornerRadius="14" Background="{DynamicResource SuccessIcon}" BorderBrush="{DynamicResource Green}" BorderThickness="1"><Path Data="M 1,5 L 4,8 L 10,1" Stroke="{DynamicResource Green}" StrokeThickness="2" StrokeStartLineCap="Round" StrokeEndLineCap="Round" Width="11" Height="9" Stretch="Fill" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><TextBlock Text="Reduce" Foreground="{DynamicResource Subtext0}" Margin="0,4,0,0"/></StackPanel>
              <StackPanel Grid.Column="2" HorizontalAlignment="Center"><Border Width="28" Height="28" CornerRadius="14" Background="{DynamicResource SuccessIcon}" BorderBrush="{DynamicResource Green}" BorderThickness="1"><Path Data="M 1,5 L 4,8 L 10,1" Stroke="{DynamicResource Green}" StrokeThickness="2" StrokeStartLineCap="Round" StrokeEndLineCap="Round" Width="11" Height="9" Stretch="Fill" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><TextBlock Text="Correlate" Foreground="{DynamicResource Subtext0}" Margin="0,4,0,0"/></StackPanel>
              <StackPanel Grid.Column="3" HorizontalAlignment="Center"><Border Width="28" Height="28" CornerRadius="14" Background="{DynamicResource SuccessIcon}" BorderBrush="{DynamicResource Green}" BorderThickness="1"><Path Data="M 1,5 L 4,8 L 10,1" Stroke="{DynamicResource Green}" StrokeThickness="2" StrokeStartLineCap="Round" StrokeEndLineCap="Round" Width="11" Height="9" Stretch="Fill" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><TextBlock Text="Resolve" Foreground="{DynamicResource Subtext0}" Margin="0,4,0,0"/></StackPanel>
              <StackPanel Grid.Column="4" HorizontalAlignment="Center"><Border Width="28" Height="28" CornerRadius="14" Background="{DynamicResource SuccessIcon}" BorderBrush="{DynamicResource Green}" BorderThickness="1"><Path Data="M 1,5 L 4,8 L 10,1" Stroke="{DynamicResource Green}" StrokeThickness="2" StrokeStartLineCap="Round" StrokeEndLineCap="Round" Width="11" Height="9" Stretch="Fill" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><TextBlock Text="Report" Foreground="{DynamicResource Subtext0}" Margin="0,4,0,0"/></StackPanel>
            </Grid>
            <Grid Grid.Row="1" Margin="0,9,0,0">
              <TextBlock x:Name="TxtActivityHeadline" Text="Run a scan to see each stage here"
                         Foreground="{DynamicResource Text}" FontSize="16" FontWeight="SemiBold" VerticalAlignment="Center"/>
              <Button x:Name="BtnActivityRunAgain" Style="{StaticResource AccentButton}" Content="Run scan"
                      HorizontalAlignment="Right" Padding="13,7"/>
            </Grid>
          </Grid>
        </Border>

        <Grid Grid.Row="2">
          <Grid.ColumnDefinitions><ColumnDefinition Width="1.8*"/><ColumnDefinition Width="1*"/></Grid.ColumnDefinitions>
          <Border Grid.Column="0" Style="{StaticResource Card}" Padding="0" Margin="0,0,10,0">
            <Grid>
              <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
              <Grid Grid.Row="0" Margin="15,12,15,9">
                <TextBlock Text="Scan activity" Foreground="{DynamicResource Text}" FontSize="15" FontWeight="SemiBold"/>
                <TextBlock x:Name="TxtActivityLastLine" Text="" HorizontalAlignment="Right" VerticalAlignment="Center"
                           Foreground="{DynamicResource TextMuted}" FontSize="10" TextTrimming="CharacterEllipsis" MaxWidth="380"/>
              </Grid>
              <TextBox x:Name="TxtActivityLog" Grid.Row="1" IsReadOnly="True" TextWrapping="NoWrap"
                       AutomationProperties.Name="Scan activity log"
                       Background="{DynamicResource LogBackground}" BorderBrush="{DynamicResource Surface1}" BorderThickness="0,1,0,1"
                       Padding="14,10" FontFamily="Consolas" FontSize="11.5" Foreground="{DynamicResource Subtext0}"
                       VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" Text=""/>
              <Grid Grid.Row="2" Margin="12,10">
                <TextBox x:Name="TxtActivitySearch" Text=""
                         AutomationProperties.Name="Filter activity messages"/>
                <TextBlock x:Name="TxtActivitySearchHint" Text="Filter activity messages"
                           IsHitTestVisible="False" Margin="10,0,0,0" VerticalAlignment="Center"
                           Foreground="{DynamicResource TextMuted}" FontSize="11"/>
              </Grid>
            </Grid>
          </Border>

          <StackPanel Grid.Column="1">
            <Border Style="{StaticResource Card}" Padding="14">
              <StackPanel>
                <TextBlock Text="Run summary" Foreground="{DynamicResource Text}" FontSize="15" FontWeight="SemiBold"/>
                <Grid Margin="0,10,0,0"><TextBlock Text="Duration" Foreground="{DynamicResource TextMuted}"/><TextBlock x:Name="TxtActivityDuration" Text="-" HorizontalAlignment="Right" Foreground="{DynamicResource Text}"/></Grid>
                <Grid Margin="0,7,0,0"><TextBlock Text="Records" Foreground="{DynamicResource TextMuted}"/><TextBlock x:Name="TxtActivityRecords" Text="-" HorizontalAlignment="Right" Foreground="{DynamicResource Text}"/></Grid>
                <Grid Margin="0,7,0,0"><TextBlock Text="Signatures" Foreground="{DynamicResource TextMuted}"/><TextBlock x:Name="TxtActivitySignatures" Text="-" HorizontalAlignment="Right" Foreground="{DynamicResource Text}"/></Grid>
                <Grid Margin="0,7,0,0"><TextBlock Text="Rules" Foreground="{DynamicResource TextMuted}"/><TextBlock x:Name="TxtActivityRules" Text="-" HorizontalAlignment="Right" Foreground="{DynamicResource Text}"/></Grid>
              </StackPanel>
            </Border>

            <Border Style="{StaticResource Card}" Padding="14" Margin="0,9,0,0">
              <StackPanel>
                <TextBlock Text="Report" Foreground="{DynamicResource Text}" FontSize="15" FontWeight="SemiBold"/>
                <TextBlock x:Name="TxtActivityReportState" Text="Not saved yet" Foreground="{DynamicResource TextMuted}" Margin="0,3,0,0"/>
                <StackPanel Orientation="Horizontal" Margin="0,11,0,0">
                  <Button x:Name="BtnActivitySave" Style="{StaticResource BaseButton}" Content="Save report" Padding="9,6"/>
                  <Button x:Name="BtnActivityOpen" Style="{StaticResource BaseButton}" Content="Open report" Padding="9,6" Margin="7,0,0,0"/>
                </StackPanel>
              </StackPanel>
            </Border>

            <Border Style="{StaticResource Card}" Padding="14" Margin="0,9,0,0">
              <StackPanel Orientation="Horizontal">
                <Border Width="34" Height="34" CornerRadius="17" Background="{DynamicResource BluePanel}" BorderBrush="{DynamicResource Blue}" BorderThickness="1"><TextBlock Text="R" Foreground="{DynamicResource Blue}" HorizontalAlignment="Center" VerticalAlignment="Center" FontWeight="Bold"/></Border>
                <StackPanel Margin="11,0,0,0"><TextBlock Text="Read-only guarantee" Foreground="{DynamicResource Text}" FontWeight="SemiBold"/><TextBlock Text="LogVerdict only reads diagnostic sources. Nothing on this machine was changed." MaxWidth="235" TextWrapping="Wrap" Foreground="{DynamicResource TextMuted}" FontSize="10.5" LineHeight="16" Margin="0,4,0,0"/></StackPanel>
              </StackPanel>
            </Border>
          </StackPanel>
        </Grid>
      </Grid>
    </Grid>

    <!-- ============ Status bar ============ -->
    <Border Grid.Column="1" Grid.Row="2" Background="{DynamicResource Mantle}" BorderBrush="{DynamicResource Surface0}"
            BorderThickness="0,1,0,0">
      <StackPanel>
        <ProgressBar x:Name="PbScan" IsIndeterminate="False" Visibility="Collapsed"/>
        <Grid Margin="20,9,20,9">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock x:Name="TxtStatus" Grid.Column="0" VerticalAlignment="Center" FontSize="12"
                     TextTrimming="CharacterEllipsis" Foreground="{DynamicResource Subtext0}"
                     Text="Ready."/>
          <TextBlock x:Name="TxtFooter" Grid.Column="1" VerticalAlignment="Center" FontSize="11"
                     Foreground="{DynamicResource TextMuted}" Text=""/>
        </Grid>
      </StackPanel>
    </Border>

  </Grid>
</Window>
'@
    return ConvertTo-LVLocalizedXaml -Xaml $xaml
}
