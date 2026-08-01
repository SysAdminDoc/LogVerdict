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

    return @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="LogVerdict"
    Height="760" Width="1340" MinHeight="560" MinWidth="1040"
    WindowStartupLocation="CenterScreen"
    Background="#1e1e2e"
    TextOptions.TextFormattingMode="Ideal"
    UseLayoutRounding="True"
    FontFamily="Segoe UI Variable Text, Segoe UI"
    FontSize="13">

  <Window.Resources>

    <SolidColorBrush x:Key="Base"     Color="#1e1e2e"/>
    <SolidColorBrush x:Key="Mantle"   Color="#181825"/>
    <SolidColorBrush x:Key="Crust"    Color="#11111b"/>
    <SolidColorBrush x:Key="Surface0" Color="#313244"/>
    <SolidColorBrush x:Key="Surface1" Color="#45475a"/>
    <SolidColorBrush x:Key="Surface2" Color="#585b70"/>
    <SolidColorBrush x:Key="Overlay0" Color="#6c7086"/>
    <SolidColorBrush x:Key="Overlay1" Color="#7f849c"/>
    <SolidColorBrush x:Key="Text"     Color="#cdd6f4"/>
    <SolidColorBrush x:Key="Subtext1" Color="#bac2de"/>
    <SolidColorBrush x:Key="Subtext0" Color="#a6adc8"/>
    <SolidColorBrush x:Key="Blue"     Color="#89b4fa"/>
    <SolidColorBrush x:Key="Lavender" Color="#b4befe"/>
    <SolidColorBrush x:Key="Mauve"    Color="#cba6f7"/>
    <SolidColorBrush x:Key="Red"      Color="#f38ba8"/>
    <SolidColorBrush x:Key="Peach"    Color="#fab387"/>
    <SolidColorBrush x:Key="Yellow"   Color="#f9e2af"/>
    <SolidColorBrush x:Key="Green"    Color="#a6e3a1"/>
    <SolidColorBrush x:Key="Sky"      Color="#89dceb"/>

    <!-- Muted TEXT. Overlay0 and Overlay1 are dim enough to fail WCAG AA for body text
         (measured 3.36:1 and 4.44:1 on base), so they are now used only for borders and
         dividers, where the 3:1 non-text threshold applies. This tone measures 5.81:1 on
         base, 6.22:1 on mantle and 6.64:1 on crust - it clears AA on every surface the
         window actually paints text on. Same value the HTML report uses, so the two
         outputs stay visually consistent. -->
    <SolidColorBrush x:Key="TextMuted" Color="#9399b2"/>

    <!-- A custom ControlTemplate keeps the framework's dotted focus adorner, which is
         effectively invisible on a dark surface. WCAG 2.4.7 wants focus visible and
         1.4.11 wants it at 3:1, so keyboard focus draws an accent ring instead.
         Unrelated to the no-keyboard-shortcuts policy: this is focus visibility, not
         an accelerator. -->
    <Style x:Key="LVFocusVisual">
      <Setter Property="Control.Template">
        <Setter.Value>
          <ControlTemplate>
            <Rectangle Margin="-3" StrokeThickness="2" Stroke="#89b4fa"
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
            <Border x:Name="Bar" CornerRadius="4" Margin="3,2,3,2" Background="#45475a"/>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bar" Property="Background" Value="#6c7086"/>
              </Trigger>
              <Trigger Property="IsDragging" Value="True">
                <Setter TargetName="Bar" Property="Background" Value="#7f849c"/>
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
      <Setter Property="FocusVisualStyle" Value="{StaticResource LVFocusVisual}"/>
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="Background" Value="{StaticResource Surface0}"/>
      <Setter Property="BorderBrush" Value="{StaticResource Surface1}"/>
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
                <Setter TargetName="Chrome" Property="Background" Value="{StaticResource Surface1}"/>
                <Setter TargetName="Chrome" Property="BorderBrush" Value="{StaticResource Surface2}"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="Chrome" Property="Background" Value="{StaticResource Surface2}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="Chrome" Property="Background" Value="{StaticResource Mantle}"/>
                <Setter TargetName="Chrome" Property="BorderBrush" Value="{StaticResource Surface0}"/>
                <Setter Property="Foreground" Value="{StaticResource Overlay0}"/>
                <Setter Property="Cursor" Value="Arrow"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="AccentButton" TargetType="Button" BasedOn="{StaticResource BaseButton}">
      <Setter Property="FocusVisualStyle" Value="{StaticResource LVFocusVisual}"/>
      <Setter Property="Foreground" Value="#11111b"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="14,9"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Chrome" Background="#89b4fa" CornerRadius="6">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                                Margin="{TemplateBinding Padding}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Chrome" Property="Background" Value="#b4befe"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="Chrome" Property="Background" Value="#74a8fc"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="Chrome" Property="Background" Value="{StaticResource Surface0}"/>
                <Setter Property="Foreground" Value="{StaticResource Overlay0}"/>
                <Setter Property="Cursor" Value="Arrow"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Verdict chips double as the filter. Checked = that verdict is visible. -->
    <Style x:Key="ChipToggle" TargetType="ToggleButton">
      <Setter Property="FocusVisualStyle" Value="{StaticResource LVFocusVisual}"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Margin" Value="0,0,0,6"/>
      <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
      <Setter Property="Foreground" Value="{StaticResource Subtext0}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ToggleButton">
            <Border x:Name="Chrome" CornerRadius="6" Background="{StaticResource Mantle}"
                    BorderBrush="{StaticResource Surface0}" BorderThickness="1" Padding="10,7">
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
                <Setter TargetName="Chrome" Property="Background" Value="{StaticResource Surface0}"/>
                <Setter TargetName="Chrome" Property="BorderBrush" Value="{StaticResource Surface2}"/>
                <Setter Property="Foreground" Value="{StaticResource Text}"/>
              </Trigger>
              <Trigger Property="IsChecked" Value="False">
                <Setter TargetName="Dot" Property="Opacity" Value="0.25"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Chrome" Property="BorderBrush" Value="{StaticResource Overlay0}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="CheckBox">
      <Setter Property="FocusVisualStyle" Value="{StaticResource LVFocusVisual}"/>
      <Setter Property="Foreground" Value="{StaticResource Subtext1}"/>
      <Setter Property="Margin" Value="0,0,0,9"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="CheckBox">
            <StackPanel Orientation="Horizontal" Background="Transparent">
              <Border x:Name="Box" Width="16" Height="16" CornerRadius="4"
                      Background="{StaticResource Crust}" BorderBrush="{StaticResource Surface2}"
                      BorderThickness="1" VerticalAlignment="Center">
                <Path x:Name="Tick" Visibility="Collapsed" Stretch="Uniform" Margin="3"
                      Data="M 0,5 L 4,9 L 11,0" Stroke="#11111b" StrokeThickness="2.2"
                      StrokeEndLineCap="Round" StrokeStartLineCap="Round"/>
              </Border>
              <ContentPresenter Margin="9,0,0,0" VerticalAlignment="Center"/>
            </StackPanel>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Box" Property="Background" Value="{StaticResource Blue}"/>
                <Setter TargetName="Box" Property="BorderBrush" Value="{StaticResource Blue}"/>
                <Setter TargetName="Tick" Property="Visibility" Value="Visible"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Box" Property="BorderBrush" Value="{StaticResource Lavender}"/>
                <Setter Property="Foreground" Value="{StaticResource Text}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Foreground" Value="{StaticResource Overlay0}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="TextBox">
      <Setter Property="FocusVisualStyle" Value="{StaticResource LVFocusVisual}"/>
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="CaretBrush" Value="{StaticResource Blue}"/>
      <Setter Property="SelectionBrush" Value="{StaticResource Blue}"/>
      <Setter Property="Background" Value="{StaticResource Crust}"/>
      <Setter Property="BorderBrush" Value="{StaticResource Surface1}"/>
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
                <Setter TargetName="Chrome" Property="BorderBrush" Value="{StaticResource Blue}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Section heading inside the detail pane -->
    <Style x:Key="SectionLabel" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource TextMuted}"/>
      <Setter Property="FontSize" Value="10.5"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Margin" Value="0,16,0,5"/>
    </Style>

    <Style x:Key="BodyText" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource Subtext1}"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="LineHeight" Value="19"/>
    </Style>

    <Style x:Key="PanelLabel" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource TextMuted}"/>
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
      <Setter Property="Foreground" Value="{StaticResource Subtext1}"/>
      <Setter Property="Padding" Value="0"/>
      <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ListViewItem">
            <Border x:Name="Row" Background="Transparent" BorderThickness="0,0,0,1"
                    BorderBrush="#232334" Padding="0,7">
              <GridViewRowPresenter VerticalAlignment="Center"
                                    Columns="{TemplateBinding GridView.ColumnCollection}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Row" Property="Background" Value="#252539"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Row" Property="Background" Value="{StaticResource Surface0}"/>
                <Setter Property="Foreground" Value="{StaticResource Text}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="GridViewColumnHeader">
      <Setter Property="Foreground" Value="{StaticResource TextMuted}"/>
      <Setter Property="FontSize" Value="10.5"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="HorizontalContentAlignment" Value="Left"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="GridViewColumnHeader">
            <Border x:Name="Chrome" Background="{StaticResource Mantle}"
                    BorderBrush="{StaticResource Surface0}" BorderThickness="0,0,0,1"
                    Padding="10,8">
              <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Chrome" Property="Background" Value="{StaticResource Surface0}"/>
                <Setter Property="Foreground" Value="{StaticResource Text}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="GridSplitter">
      <Setter Property="Background" Value="{StaticResource Mantle}"/>
      <Setter Property="Width" Value="5"/>
    </Style>

    <Style TargetType="ProgressBar">
      <Setter Property="Foreground" Value="{StaticResource Blue}"/>
      <Setter Property="Background" Value="{StaticResource Surface0}"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Height" Value="3"/>
    </Style>

  </Window.Resources>

  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- ============ Header ============ -->
    <Border Grid.Row="0" Background="{StaticResource Mantle}" BorderBrush="{StaticResource Surface0}"
            BorderThickness="0,0,0,1" Padding="20,14">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>

        <StackPanel Grid.Column="0" Orientation="Horizontal">
          <Border Width="34" Height="34" CornerRadius="8" Background="{StaticResource Blue}"
                  VerticalAlignment="Center">
            <TextBlock Text="LV" Foreground="#11111b" FontWeight="Bold" FontSize="14"
                       HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Border>
          <StackPanel Margin="12,0,0,0" VerticalAlignment="Center">
            <StackPanel Orientation="Horizontal">
              <TextBlock Text="LogVerdict" Foreground="{StaticResource Text}" FontSize="17"
                         FontWeight="SemiBold"/>
              <TextBlock x:Name="TxtVersion" Foreground="{StaticResource TextMuted}" FontSize="11"
                         Margin="8,0,0,0" VerticalAlignment="Bottom" Text="v0.0.0"/>
            </StackPanel>
            <TextBlock Text="What your logs actually say, in plain English"
                       Foreground="{StaticResource TextMuted}" FontSize="11.5" Margin="0,1,0,0"/>
          </StackPanel>
        </StackPanel>

        <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
          <TextBlock x:Name="TxtMachine" Foreground="{StaticResource Subtext0}" FontSize="12"
                     VerticalAlignment="Center" Margin="0,0,14,0" Text=""/>
          <Border x:Name="ChipElevation" CornerRadius="5" Padding="9,4" Background="{StaticResource Surface0}">
            <TextBlock x:Name="TxtElevation" Foreground="{StaticResource Subtext0}" FontSize="11" Text=""/>
          </Border>
        </StackPanel>
      </Grid>
    </Border>

    <!-- ============ Elevation notice ============ -->
    <Border x:Name="PnlElevate" Grid.Row="1" Background="#2a2438" BorderBrush="#45475a"
            BorderThickness="0,0,0,1" Padding="20,10" Visibility="Collapsed">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <TextBlock Grid.Column="0" VerticalAlignment="Center" TextWrapping="Wrap"
                   Foreground="{StaticResource Subtext1}" FontSize="12"
                   Text="Running without administrator rights. The Security channel and some setup logs cannot be read, so a clean result here is not proof the machine is healthy."/>
        <Button x:Name="BtnElevate" Grid.Column="1" Style="{StaticResource BaseButton}"
                Margin="16,0,0,0" Content="Restart as administrator"/>
      </Grid>
    </Border>

    <!-- ============ Body ============ -->
    <Grid Grid.Row="2">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="298"/>
        <ColumnDefinition Width="*" MinWidth="380"/>
        <ColumnDefinition Width="5"/>
        <ColumnDefinition Width="404" MinWidth="280"/>
      </Grid.ColumnDefinitions>

      <!-- ==== Left: controls ==== -->
      <Border Grid.Column="0" Background="{StaticResource Mantle}" BorderBrush="{StaticResource Surface0}"
              BorderThickness="0,0,1,0">
        <ScrollViewer VerticalScrollBarVisibility="Auto">
          <StackPanel Margin="18,18,18,18">

            <TextBlock Text="SCAN" Style="{StaticResource PanelLabel}"/>

            <TextBlock x:Name="LblDays" Text="Look back this many days" Foreground="{StaticResource Subtext0}"
                       FontSize="12" Margin="0,0,0,6"/>
            <!-- Both, deliberately. LabeledBy records the relationship to the visible
                 caption; Name guarantees the announcement, because the LabeledBy
                 fallback only fires when the peer is reached through a connected tree
                 and returns nothing for a peer created directly against the element. -->
            <TextBox x:Name="TxtDays" Text="30" Margin="0,0,0,12"
                     AutomationProperties.LabeledBy="{Binding ElementName=LblDays}"
                     AutomationProperties.Name="Look back this many days"/>

            <CheckBox x:Name="ChkAllChannels" Content="Sweep every event channel"/>
            <CheckBox x:Name="ChkSkipText" Content="Skip CBS / DISM / setup logs"/>
            <CheckBox x:Name="ChkIncludeBenign" Content="Show signatures ruled harmless"/>

            <Button x:Name="BtnScan" Style="{StaticResource AccentButton}" Margin="0,10,0,0"
                    Content="Run scan"/>
            <Button x:Name="BtnCancel" Style="{StaticResource BaseButton}" Margin="0,8,0,0"
                    Content="Cancel" Visibility="Collapsed"/>

            <!-- ==== Summary ==== -->
            <StackPanel x:Name="PnlSummary" Visibility="Collapsed">
              <TextBlock Text="VERDICTS" Style="{StaticResource PanelLabel}" Margin="0,26,0,9"/>
              <TextBlock Foreground="{StaticResource TextMuted}" FontSize="11" TextWrapping="Wrap"
                         Margin="0,-4,0,9" Text="Click to show or hide a verdict."/>

              <ToggleButton x:Name="ChipCritical"    Style="{StaticResource ChipToggle}" Tag="#f38ba8" IsChecked="True"/>
              <ToggleButton x:Name="ChipActionable"  Style="{StaticResource ChipToggle}" Tag="#fab387" IsChecked="True"/>
              <ToggleButton x:Name="ChipInvestigate" Style="{StaticResource ChipToggle}" Tag="#f9e2af" IsChecked="True"/>
              <ToggleButton x:Name="ChipUnknown"     Style="{StaticResource ChipToggle}" Tag="#b4befe" IsChecked="True"/>
              <ToggleButton x:Name="ChipInformational" Style="{StaticResource ChipToggle}" Tag="#89dceb" IsChecked="True"/>
              <ToggleButton x:Name="ChipBenign"      Style="{StaticResource ChipToggle}" Tag="#a6e3a1" IsChecked="True"/>

              <TextBlock Text="CORPUS" Style="{StaticResource PanelLabel}" Margin="0,22,0,9"/>
              <Border Background="{StaticResource Base}" CornerRadius="6" Padding="12,10">
                <StackPanel>
                  <Grid Margin="0,0,0,5">
                    <TextBlock Text="Records read" Foreground="{StaticResource TextMuted}" FontSize="11.5"/>
                    <TextBlock x:Name="TxtRecords" HorizontalAlignment="Right"
                               Foreground="{StaticResource Text}" FontSize="11.5" Text="-"/>
                  </Grid>
                  <Grid Margin="0,0,0,5">
                    <TextBlock Text="Distinct signatures" Foreground="{StaticResource TextMuted}" FontSize="11.5"/>
                    <TextBlock x:Name="TxtSignatures" HorizontalAlignment="Right"
                               Foreground="{StaticResource Text}" FontSize="11.5" Text="-"/>
                  </Grid>
                  <Grid Margin="0,0,0,5">
                    <TextBlock Text="Noise removed" Foreground="{StaticResource TextMuted}" FontSize="11.5"/>
                    <TextBlock x:Name="TxtReduction" HorizontalAlignment="Right"
                               Foreground="{StaticResource Green}" FontSize="11.5" Text="-"/>
                  </Grid>
                  <Grid>
                    <TextBlock Text="Rules applied" Foreground="{StaticResource TextMuted}" FontSize="11.5"/>
                    <TextBlock x:Name="TxtRules" HorizontalAlignment="Right"
                               Foreground="{StaticResource Text}" FontSize="11.5" Text="-"/>
                  </Grid>
                </StackPanel>
              </Border>
            </StackPanel>

            <!-- ==== Coverage gaps ==== -->
            <StackPanel x:Name="PnlCoverage" Visibility="Collapsed">
              <TextBlock Text="WHAT THIS SCAN COULD NOT SEE" Style="{StaticResource PanelLabel}"
                         Margin="0,22,0,9" TextWrapping="Wrap"/>
              <Border Background="#2a2438" CornerRadius="6" Padding="12,10">
                <ItemsControl x:Name="LstCoverage">
                  <ItemsControl.ItemTemplate>
                    <DataTemplate>
                      <TextBlock Text="{Binding}" TextWrapping="Wrap" Margin="0,0,0,7"
                                 Foreground="{StaticResource Subtext0}" FontSize="11.5" LineHeight="17"/>
                    </DataTemplate>
                  </ItemsControl.ItemTemplate>
                </ItemsControl>
              </Border>
            </StackPanel>

          </StackPanel>
        </ScrollViewer>
      </Border>

      <!-- ==== Centre: findings ==== -->
      <Grid Grid.Column="1">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <Grid Grid.Row="0" Margin="16,14,16,10">
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
                     Foreground="{StaticResource TextMuted}" FontSize="12.5"
                     Text="Filter by title, provider, event id or message"/>
          <TextBlock x:Name="TxtShown" Grid.Column="1" Margin="14,0,0,0" VerticalAlignment="Center"
                     Foreground="{StaticResource TextMuted}" FontSize="11.5" Text=""/>
        </Grid>

        <ListView x:Name="LvFindings" Grid.Row="1" Background="Transparent" BorderThickness="0"
                  Margin="16,0,16,14"
                  AutomationProperties.Name="Findings, worst first"
                  ItemContainerStyle="{StaticResource FindingRow}"
                  ScrollViewer.HorizontalScrollBarVisibility="Disabled">
          <ListView.View>
            <GridView AllowsColumnReorder="False">
              <GridViewColumn Header="VERDICT" Width="108">
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
              <GridViewColumn Header="WHAT HAPPENED" Width="372">
                <GridViewColumn.CellTemplate>
                  <DataTemplate>
                    <TextBlock Text="{Binding Title}" TextTrimming="CharacterEllipsis"
                               ToolTip="{Binding Title}" Margin="0,0,10,0"/>
                  </DataTemplate>
                </GridViewColumn.CellTemplate>
              </GridViewColumn>
              <GridViewColumn Header="TIMES" Width="66">
                <GridViewColumn.CellTemplate>
                  <DataTemplate>
                    <TextBlock Text="{Binding Count}" HorizontalAlignment="Right" Margin="0,0,16,0"/>
                  </DataTemplate>
                </GridViewColumn.CellTemplate>
              </GridViewColumn>
              <GridViewColumn Header="PER DAY" Width="72">
                <GridViewColumn.CellTemplate>
                  <DataTemplate>
                    <TextBlock Text="{Binding PerDayText}" HorizontalAlignment="Right" Margin="0,0,16,0"
                               Foreground="{StaticResource Subtext0}"/>
                  </DataTemplate>
                </GridViewColumn.CellTemplate>
              </GridViewColumn>
              <GridViewColumn Header="LAST SEEN" Width="128">
                <GridViewColumn.CellTemplate>
                  <DataTemplate>
                    <TextBlock Text="{Binding LastSeenText}" Foreground="{StaticResource Subtext0}"/>
                  </DataTemplate>
                </GridViewColumn.CellTemplate>
              </GridViewColumn>
              <GridViewColumn Header="WHERE FROM" Width="200">
                <GridViewColumn.CellTemplate>
                  <DataTemplate>
                    <TextBlock Text="{Binding Origin}" TextTrimming="CharacterEllipsis"
                               ToolTip="{Binding Origin}" FontFamily="Consolas" FontSize="11.5"
                               Foreground="{StaticResource TextMuted}"/>
                  </DataTemplate>
                </GridViewColumn.CellTemplate>
              </GridViewColumn>
            </GridView>
          </ListView.View>
        </ListView>

        <!-- Shown before the first scan and whenever the filter empties the list. -->
        <StackPanel x:Name="PnlEmpty" Grid.Row="1" VerticalAlignment="Center"
                    HorizontalAlignment="Center" Margin="30">
          <TextBlock x:Name="TxtEmptyTitle" HorizontalAlignment="Center" FontSize="15"
                     Foreground="{StaticResource Subtext0}" Text="Nothing scanned yet"/>
          <TextBlock x:Name="TxtEmptyBody" HorizontalAlignment="Center" Margin="0,7,0,0"
                     MaxWidth="420" TextAlignment="Center" TextWrapping="Wrap" LineHeight="19"
                     Foreground="{StaticResource TextMuted}" FontSize="12.5"
                     Text="Press Run scan. LogVerdict reads this machine's event channels and setup logs, collapses the repeats, and rules on what is left. Nothing is modified."/>
        </StackPanel>
      </Grid>

      <GridSplitter Grid.Column="2" HorizontalAlignment="Stretch" VerticalAlignment="Stretch"/>

      <!-- ==== Right: detail ==== -->
      <Border Grid.Column="3" Background="{StaticResource Mantle}" BorderBrush="{StaticResource Surface0}"
              BorderThickness="1,0,0,0">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>

          <TextBlock x:Name="TxtNoSelection" Grid.Row="0" VerticalAlignment="Center"
                     HorizontalAlignment="Center" Margin="30" TextAlignment="Center"
                     TextWrapping="Wrap" Foreground="{StaticResource TextMuted}" FontSize="12.5"
                     Text="Select a finding to see what it means and what to do about it."/>

          <ScrollViewer x:Name="ScrDetail" Grid.Row="0" VerticalScrollBarVisibility="Auto"
                        Visibility="Collapsed" Padding="20,18,14,18">
            <StackPanel>
              <Border x:Name="PillDetail" CornerRadius="4" Padding="8,3" HorizontalAlignment="Left"
                      Background="{StaticResource Surface0}">
                <TextBlock x:Name="TxtDetailVerdict" FontSize="10.5" FontWeight="SemiBold" Text=""/>
              </Border>

              <TextBlock x:Name="TxtDetailTitle" Margin="0,11,0,0" FontSize="16" FontWeight="SemiBold"
                         TextWrapping="Wrap" LineHeight="22" Foreground="{StaticResource Text}" Text=""/>
              <TextBlock x:Name="TxtDetailMeta" Margin="0,7,0,0" FontSize="11.5" TextWrapping="Wrap"
                         Foreground="{StaticResource TextMuted}" FontFamily="Consolas" Text=""/>

              <TextBlock Text="IN PLAIN ENGLISH" Style="{StaticResource SectionLabel}"/>
              <TextBlock x:Name="TxtPlain" Style="{StaticResource BodyText}" Text=""/>

              <TextBlock Text="WHY THIS RULING" Style="{StaticResource SectionLabel}"/>
              <TextBlock x:Name="TxtWhy" Style="{StaticResource BodyText}" Text=""/>

              <TextBlock Text="WHAT TO DO" Style="{StaticResource SectionLabel}"/>
              <Border Background="{StaticResource Base}" CornerRadius="6" Padding="12,10"
                      BorderBrush="{StaticResource Surface0}" BorderThickness="1">
                <TextBlock x:Name="TxtAction" Style="{StaticResource BodyText}"
                           Foreground="{StaticResource Text}" Text=""/>
              </Border>

              <StackPanel x:Name="PnlFalsePositives" Visibility="Collapsed">
                <TextBlock Text="COULD ALSO BE INNOCENT WHEN" Style="{StaticResource SectionLabel}"/>
                <ItemsControl x:Name="LstFalsePositives">
                  <ItemsControl.ItemTemplate>
                    <DataTemplate>
                      <TextBlock Text="{Binding}" TextWrapping="Wrap" Margin="0,0,0,5"
                                 Foreground="{StaticResource Subtext0}" FontSize="12" LineHeight="18"/>
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
                        <Hyperlink NavigateUri="{Binding}" Foreground="#89b4fa"
                                   TextDecorations="Underline">
                          <TextBlock Text="{Binding}" TextWrapping="Wrap"/>
                        </Hyperlink>
                      </TextBlock>
                    </DataTemplate>
                  </ItemsControl.ItemTemplate>
                </ItemsControl>
              </StackPanel>

              <TextBlock Text="RAW EVIDENCE, UNEDITED" Style="{StaticResource SectionLabel}"/>
              <Border Background="{StaticResource Crust}" CornerRadius="6" Padding="12,10"
                      BorderBrush="{StaticResource Surface0}" BorderThickness="1">
                <TextBox x:Name="TxtSample" IsReadOnly="True" TextWrapping="Wrap"
                         AutomationProperties.Name="Raw evidence for the selected finding"
                         Background="Transparent" BorderThickness="0" Padding="0"
                         FontFamily="Consolas" FontSize="11.5"
                         Foreground="{StaticResource Subtext0}"
                         MaxHeight="260" VerticalScrollBarVisibility="Auto" Text=""/>
              </Border>

              <TextBlock x:Name="TxtProvenance" Margin="0,14,0,0" FontSize="11" TextWrapping="Wrap"
                         Foreground="{StaticResource TextMuted}" LineHeight="16" Text=""/>
            </StackPanel>
          </ScrollViewer>

          <Border Grid.Row="1" Background="{StaticResource Crust}" BorderBrush="{StaticResource Surface0}"
                  BorderThickness="0,1,0,0" Padding="14,11">
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
              <Button x:Name="BtnCopy" Style="{StaticResource BaseButton}" Content="Copy finding"
                      Padding="11,6" IsEnabled="False"/>
              <Button x:Name="BtnSaveReport" Style="{StaticResource BaseButton}" Margin="8,0,0,0"
                      Content="Save report" Padding="11,6" IsEnabled="False"/>
              <Button x:Name="BtnOpenReport" Style="{StaticResource BaseButton}" Margin="8,0,0,0"
                      Content="Open report" Padding="11,6" IsEnabled="False"/>
            </StackPanel>
          </Border>
        </Grid>
      </Border>
    </Grid>

    <!-- ============ Log panel ============ -->
    <Border Grid.Row="3" Background="{StaticResource Crust}" BorderBrush="{StaticResource Surface0}"
            BorderThickness="0,1,0,0">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition x:Name="RowLog" Height="0"/>
        </Grid.RowDefinitions>

        <Grid Grid.Row="0" Margin="20,0,20,0" Height="34">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Button x:Name="BtnToggleLog" Grid.Column="0" Style="{StaticResource BaseButton}"
                  Background="Transparent" BorderBrush="Transparent" Padding="0"
                  HorizontalAlignment="Left" VerticalAlignment="Center" Content="Show activity log"
                  Foreground="{StaticResource TextMuted}" FontSize="11.5"/>
          <TextBlock x:Name="TxtLastLine" Grid.Column="1" Margin="16,0,0,0" VerticalAlignment="Center"
                     TextTrimming="CharacterEllipsis" FontFamily="Consolas" FontSize="11"
                     Foreground="{StaticResource TextMuted}" Text=""/>
        </Grid>

        <TextBox x:Name="TxtLog" Grid.Row="1" Margin="20,0,20,12" IsReadOnly="True"
                 AutomationProperties.Name="Scan activity log"
                 Background="Transparent" BorderThickness="0" Padding="0"
                 FontFamily="Consolas" FontSize="11.5" Foreground="{StaticResource Subtext0}"
                 VerticalScrollBarVisibility="Auto" TextWrapping="NoWrap"
                 HorizontalScrollBarVisibility="Auto" Text=""/>
      </Grid>
    </Border>

    <!-- ============ Status bar ============ -->
    <Border Grid.Row="4" Background="{StaticResource Mantle}" BorderBrush="{StaticResource Surface0}"
            BorderThickness="0,1,0,0">
      <StackPanel>
        <ProgressBar x:Name="PbScan" IsIndeterminate="False" Visibility="Collapsed"/>
        <Grid Margin="20,9,20,9">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock x:Name="TxtStatus" Grid.Column="0" VerticalAlignment="Center" FontSize="12"
                     TextTrimming="CharacterEllipsis" Foreground="{StaticResource Subtext0}"
                     Text="Ready."/>
          <TextBlock x:Name="TxtFooter" Grid.Column="1" VerticalAlignment="Center" FontSize="11"
                     Foreground="{StaticResource TextMuted}" Text=""/>
        </Grid>
      </StackPanel>
    </Border>

  </Grid>
</Window>
'@
}
